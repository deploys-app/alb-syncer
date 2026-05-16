package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	certificatemanager "cloud.google.com/go/certificatemanager/apiv1"
	"cloud.google.com/go/certificatemanager/apiv1/certificatemanagerpb"
	"cloud.google.com/go/pubsub"
	"github.com/acoshift/configfile"
	"github.com/acoshift/pgsql"
	"github.com/acoshift/pgsql/pgctx"
	"github.com/asaskevich/govalidator"
	"github.com/deploys-app/api"
	"github.com/lib/pq"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func main() {
	cfg := configfile.NewEnvReader()

	slog.Info("start alb-syncer")

	db, err := sql.Open("postgres", cfg.MustString("db_url"))
	if err != nil {
		slog.Error("can not open database", "error", err)
		os.Exit(1)
	}
	defer db.Close()

	db.SetMaxIdleConns(1)
	db.SetConnMaxIdleTime(time.Minute)

	ctx := context.Background()

	cm, err := certificatemanager.NewClient(ctx)
	if err != nil {
		slog.Error("can not create certificate manager client", "error", err)
		os.Exit(1)
	}
	defer cm.Close()

	w := Worker{
		Client:         cm,
		DB:             db,
		LocationID:     cfg.MustString("location_id"),
		ALBProjectID:   cfg.MustString("alb_project_id"),
		CertificateMap: cfg.MustString("certificate_map"),
	}

	chEvent := make(chan struct{})

	projectID := cfg.String("project_id")
	var pubSubClient *pubsub.Client
	if projectID != "" { // optional
		pubSubClient, err = pubsub.NewClient(ctx, projectID)
		if err != nil {
			slog.Error("can not create pubsub client", "error", err)
			os.Exit(1)
		}

		const topic = "event"
		const subscription = "alb-syncer.event"

		if pubSubClient != nil {
			defer pubSubClient.Close()

			_, err = pubSubClient.CreateSubscription(ctx, subscription, pubsub.SubscriptionConfig{
				Topic:             pubSubClient.Topic(topic),
				AckDeadline:       10 * time.Second,
				RetentionDuration: time.Hour,
				ExpirationPolicy:  24 * time.Hour,
			})
			if err != nil {
				slog.Info("creating subscription error", "error", err)
			}

			go func() {
				err := pubSubClient.Subscription(subscription).Receive(ctx, func(ctx context.Context, msg *pubsub.Message) {
					slog.Info("received event", "data", string(msg.Data))

					msg.Ack()

					select {
					case chEvent <- struct{}{}:
					default:
					}
				})
				if err != nil {
					slog.Error("subscribe failed", "error", err)
					if !cfg.Bool("local") {
						os.Exit(1)
					}
				}
			}()
		}
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGTERM)

	for {
		w.Run()

		select {
		case <-stop:
			return
		case <-time.After(10 * time.Second):
		case <-chEvent:
		}
	}
}

type Worker struct {
	Client         *certificatemanager.Client
	DB             *sql.DB
	LocationID     string
	ALBProjectID   string
	CertificateMap string

	lastPending    time.Time
	pendingRunning uint32
	lastStatus     time.Time
	statusRunning  uint32
}

func (w *Worker) Run() {
	ctx := context.Background()
	ctx = pgctx.NewContext(ctx, w.DB)

	ds, err := w.getPendingDomains(ctx)
	if err != nil {
		slog.Error("can not get pending domains", "error", err)
		return
	}

	for _, d := range ds {
		slog.Info("processing", "id", d.ID, "location", d.LocationID, "domain", d.Domain, "action", d.Action)

		var err error
		switch {
		case d.Action == api.Create && d.CDN:
			err = w.createDomain(ctx, d)
		case d.Action == api.Create && !d.CDN:
			slog.Info("domain pending but not cdn, deleting...", "domain", d.Domain)
			err = w.deleteDomain(ctx, d)
		case d.Action == api.Delete:
			err = w.deleteDomain(ctx, d)
		}
		if err != nil {
			slog.Error("process error", "error", err)
		}
	}

	if atomic.LoadUint32(&w.pendingRunning) == 0 && time.Since(w.lastPending) >= 10*time.Second {
		w.lastPending = time.Now()
		go func() {
			atomic.StoreUint32(&w.pendingRunning, 1)
			defer atomic.StoreUint32(&w.pendingRunning, 0)

			w.runStatusVerify()
		}()
	}

	if atomic.LoadUint32(&w.statusRunning) == 0 && time.Since(w.lastStatus) > 6*time.Hour {
		w.lastStatus = time.Now()
		go func() {
			atomic.StoreUint32(&w.statusRunning, 1)
			defer atomic.StoreUint32(&w.statusRunning, 0)

			w.runStatus()
		}()
	}

	time.Sleep(3 * time.Second)
}

func (w *Worker) runStatusVerify() {
	ctx := context.Background()
	ctx = pgctx.NewContext(ctx, w.DB)

	ds, err := w.getAllDomainsVerify(ctx)
	if err != nil {
		slog.Error("can not get all domains", "error", err)
		return
	}

	for _, d := range ds {
		if d.Action == api.Delete {
			continue
		}
		slog.Info("status-verify", "id", d.ID, "location", d.LocationID, "domain", d.Domain, "action", d.Action, "status", d.Status)
		time.Sleep(100 * time.Millisecond)

		err = w.updateStatus(ctx, d)
		if err != nil {
			slog.Error("can not update status", "error", err)
		}
	}
}

func (w *Worker) runStatus() {
	defer slog.Info("status: finished")

	ctx := context.Background()
	ctx = pgctx.NewContext(ctx, w.DB)

	ds, err := w.getAllDomainsForStatus(ctx)
	if err != nil {
		slog.Error("can not get all domains", "error", err)
		return
	}

	for _, d := range ds {
		if d.Action == api.Delete {
			continue
		}
		slog.Info("run status", "id", d.ID, "location", d.LocationID, "domain", d.Domain, "action", d.Action, "status", d.Status)
		time.Sleep(300 * time.Millisecond)

		err = w.updateStatus(ctx, d)
		if err != nil {
			slog.Error("can not update status", "domain", d.Domain, "error", err)
		}
	}
}

func (w *Worker) getPendingDomains(ctx context.Context) ([]*domain, error) {
	var xs []*domain
	err := pgctx.Iter(ctx, func(scan pgsql.Scanner) error {
		var x domain
		err := scan(
			&x.ID, &x.ProjectID, &x.LocationID, &x.Domain, &x.Wildcard, &x.CDN, &x.Action, &x.Status,
		)
		if err != nil {
			return err
		}
		xs = append(xs, &x)
		return nil
	},
		`
			select id, project_id, location_id, domain, wildcard, cdn, action, status
			from domains
			where status = $1 and location_id = $2
			order by created_at
		`, api.DomainStatusPending, w.LocationID,
	)
	if err != nil {
		return nil, err
	}
	return xs, nil
}

func (w *Worker) getAllDomainsForStatus(ctx context.Context) ([]*domain, error) {
	var xs []*domain
	err := pgctx.Iter(ctx, func(scan pgsql.Scanner) error {
		var x domain
		err := scan(
			&x.ID, &x.ProjectID, &x.LocationID, &x.Domain, &x.Wildcard, &x.CDN, &x.Action, &x.Status,
		)
		if err != nil {
			return err
		}
		xs = append(xs, &x)
		return nil
	},
		`
			select id, project_id, location_id, domain, wildcard, cdn, action, status
			from domains
			where action = $1 and status = any($2) and cdn = true and location_id = $3
			order by created_at
		`, api.Create, pq.Array([]int64{int64(api.DomainStatusSuccess), int64(api.DomainStatusError)}), w.LocationID,
	)
	if err != nil {
		return nil, err
	}
	return xs, nil
}

func (w *Worker) getAllDomainsVerify(ctx context.Context) ([]*domain, error) {
	var xs []*domain
	err := pgctx.Iter(ctx, func(scan pgsql.Scanner) error {
		var x domain
		err := scan(
			&x.ID, &x.LocationID, &x.Domain, &x.Wildcard, &x.CDN, &x.Action, &x.Status,
		)
		if err != nil {
			return err
		}
		xs = append(xs, &x)
		return nil
	},
		`
			select id, location_id, domain, wildcard, cdn, action, status
			from domains
			where action = $1 and cdn = true
			  and (status = $2 or verification->'ssl'->>'pending' = 'true')
			  and location_id = $3
			order by created_at
		`, api.Create, api.DomainStatusVerify, w.LocationID,
	)
	if err != nil {
		return nil, err
	}
	return xs, nil
}

func (w *Worker) setDomainStatus(ctx context.Context, id int64, st api.DomainStatus) error {
	_, err := pgctx.Exec(ctx, `
		update domains
		set status = $2
		where id = $1
	`, id, st)
	return err
}

func (w *Worker) setDomainVerification(ctx context.Context, id int64, info api.DomainVerification) error {
	_, err := pgctx.Exec(ctx, `
		update domains
		set verification = $2
		where id = $1
	`, id, pgsql.JSON(info))
	return err
}

func (w *Worker) getDomainAction(ctx context.Context, id int64) (api.Action, error) {
	var action api.Action
	err := pgctx.QueryRow(ctx, `
		select action
		from domains
		where id = $1
	`, id).Scan(&action)
	if err != nil {
		return action, err
	}
	return action, nil
}

func (w *Worker) removeDomain(ctx context.Context, id int64) error {
	_, err := pgctx.Exec(ctx, `
		delete from domains where id = $1
	`, id)
	return err
}

type domain struct {
	ID         int64
	ProjectID  int64
	LocationID string
	Domain     string
	Wildcard   bool
	CDN        bool
	Action     api.Action
	Status     api.DomainStatus
}

// GCP Certificate Manager resource path helpers.
// All resources live in the `global` location since alb-syncer targets the
// global external Application Load Balancer.
func (w *Worker) locationParent() string {
	return fmt.Sprintf("projects/%s/locations/global", w.ALBProjectID)
}

func (w *Worker) mapParent() string {
	return fmt.Sprintf("%s/certificateMaps/%s", w.locationParent(), w.CertificateMap)
}

func dnsAuthID(id int64) string  { return fmt.Sprintf("dns-auth-%d", id) }
func certID(id int64) string     { return fmt.Sprintf("cert-%d", id) }
func mapEntryID(id int64) string { return fmt.Sprintf("entry-%d", id) }

func (w *Worker) dnsAuthName(id int64) string {
	return fmt.Sprintf("%s/dnsAuthorizations/%s", w.locationParent(), dnsAuthID(id))
}

func (w *Worker) certName(id int64) string {
	return fmt.Sprintf("%s/certificates/%s", w.locationParent(), certID(id))
}

func (w *Worker) mapEntryName(id int64) string {
	return fmt.Sprintf("%s/certificateMapEntries/%s", w.mapParent(), mapEntryID(id))
}

func (w *Worker) createDomain(ctx context.Context, d *domain) error {
	if !govalidator.IsDNSName(d.Domain) {
		return w.setDomainStatus(ctx, d.ID, api.DomainStatusError)
	}

	if err := w.ensureDnsAuth(ctx, d); err != nil {
		return err
	}
	if err := w.ensureCertificate(ctx, d); err != nil {
		return err
	}
	if err := w.ensureMapEntry(ctx, d); err != nil {
		return err
	}

	if err := w.setDomainStatus(ctx, d.ID, api.DomainStatusVerify); err != nil {
		return err
	}
	d.Status = api.DomainStatusVerify
	return w.updateStatus(ctx, d)
}

func (w *Worker) ensureDnsAuth(ctx context.Context, d *domain) error {
	op, err := w.Client.CreateDnsAuthorization(ctx, &certificatemanagerpb.CreateDnsAuthorizationRequest{
		Parent:             w.locationParent(),
		DnsAuthorizationId: dnsAuthID(d.ID),
		DnsAuthorization: &certificatemanagerpb.DnsAuthorization{
			Domain: d.Domain,
		},
	})
	if isAlreadyExists(err) {
		return nil
	}
	if isPermanentCreateErr(err) {
		slog.Error("create dns auth permanent error, marking error", "domain", d.Domain, "error", err)
		return w.setDomainStatus(ctx, d.ID, api.DomainStatusError)
	}
	if err != nil {
		return err
	}
	if _, err := op.Wait(ctx); err != nil {
		if isAlreadyExists(err) {
			return nil
		}
		return err
	}
	return nil
}

func (w *Worker) ensureCertificate(ctx context.Context, d *domain) error {
	domains := []string{d.Domain}
	if d.Wildcard {
		domains = append(domains, "*."+d.Domain)
	}

	op, err := w.Client.CreateCertificate(ctx, &certificatemanagerpb.CreateCertificateRequest{
		Parent:        w.locationParent(),
		CertificateId: certID(d.ID),
		Certificate: &certificatemanagerpb.Certificate{
			Type: &certificatemanagerpb.Certificate_Managed{
				Managed: &certificatemanagerpb.Certificate_ManagedCertificate{
					Domains:           domains,
					DnsAuthorizations: []string{w.dnsAuthName(d.ID)},
				},
			},
		},
	})
	if isAlreadyExists(err) {
		return nil
	}
	if isPermanentCreateErr(err) {
		slog.Error("create certificate permanent error, marking error", "domain", d.Domain, "error", err)
		return w.setDomainStatus(ctx, d.ID, api.DomainStatusError)
	}
	if err != nil {
		return err
	}
	if _, err := op.Wait(ctx); err != nil {
		if isAlreadyExists(err) {
			return nil
		}
		return err
	}
	return nil
}

func (w *Worker) ensureMapEntry(ctx context.Context, d *domain) error {
	op, err := w.Client.CreateCertificateMapEntry(ctx, &certificatemanagerpb.CreateCertificateMapEntryRequest{
		Parent:                w.mapParent(),
		CertificateMapEntryId: mapEntryID(d.ID),
		CertificateMapEntry: &certificatemanagerpb.CertificateMapEntry{
			Match: &certificatemanagerpb.CertificateMapEntry_Hostname{
				Hostname: d.Domain,
			},
			Certificates: []string{w.certName(d.ID)},
		},
	})
	if isAlreadyExists(err) {
		return nil
	}
	if isPermanentCreateErr(err) {
		slog.Error("create map entry permanent error, marking error", "domain", d.Domain, "error", err)
		return w.setDomainStatus(ctx, d.ID, api.DomainStatusError)
	}
	if err != nil {
		return err
	}
	if _, err := op.Wait(ctx); err != nil {
		if isAlreadyExists(err) {
			return nil
		}
		return err
	}
	return nil
}

func (w *Worker) deleteDomain(ctx context.Context, d *domain) error {
	finalize := func() error {
		if !d.CDN {
			return w.setDomainStatus(ctx, d.ID, api.DomainStatusSuccess)
		}
		return w.removeDomain(ctx, d.ID)
	}

	// Reverse-order tear down. CertificateMapEntry must go first — its parent
	// Certificate cannot be deleted while an entry still references it, and
	// the DnsAuthorization cannot be deleted while the Certificate references it.
	if err := w.deleteMapEntry(ctx, d.ID); err != nil {
		return err
	}
	if err := w.deleteCertificate(ctx, d.ID); err != nil {
		return err
	}
	if err := w.deleteDnsAuth(ctx, d.ID); err != nil {
		return err
	}

	return finalize()
}

func (w *Worker) deleteMapEntry(ctx context.Context, id int64) error {
	op, err := w.Client.DeleteCertificateMapEntry(ctx, &certificatemanagerpb.DeleteCertificateMapEntryRequest{
		Name: w.mapEntryName(id),
	})
	if isNotFound(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := op.Wait(ctx); err != nil && !isNotFound(err) {
		return err
	}
	return nil
}

func (w *Worker) deleteCertificate(ctx context.Context, id int64) error {
	op, err := w.Client.DeleteCertificate(ctx, &certificatemanagerpb.DeleteCertificateRequest{
		Name: w.certName(id),
	})
	if isNotFound(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := op.Wait(ctx); err != nil && !isNotFound(err) {
		return err
	}
	return nil
}

func (w *Worker) deleteDnsAuth(ctx context.Context, id int64) error {
	op, err := w.Client.DeleteDnsAuthorization(ctx, &certificatemanagerpb.DeleteDnsAuthorizationRequest{
		Name: w.dnsAuthName(id),
	})
	if isNotFound(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := op.Wait(ctx); err != nil && !isNotFound(err) {
		return err
	}
	return nil
}

func (w *Worker) updateStatus(ctx context.Context, d *domain) error {
	cert, err := w.Client.GetCertificate(ctx, &certificatemanagerpb.GetCertificateRequest{
		Name: w.certName(d.ID),
	})
	if isNotFound(err) {
		slog.Warn("updateStatus: certificate not found, skip", "domain", d.Domain)
		return nil
	}
	if err != nil {
		return err
	}

	managed := cert.GetManaged()
	if managed == nil {
		slog.Warn("updateStatus: certificate not managed, skip", "domain", d.Domain)
		return nil
	}

	newStatus := managedStateToDomainStatus(managed.GetState())

	if d.Status != newStatus {
		slog.Info("updateStatus: status change", "domain", d.Domain, "from", d.Status, "to", newStatus)
		err := pgctx.RunInTx(ctx, func(ctx context.Context) error {
			action, err := w.getDomainAction(ctx, d.ID)
			if err != nil {
				return err
			}
			if action != api.Create {
				return fmt.Errorf("action stale")
			}
			return w.setDomainStatus(ctx, d.ID, newStatus)
		})
		if err != nil {
			return err
		}
	}

	var info api.DomainVerification
	info.Ownership.Errors = []string{}
	info.SSL.Errors = []string{}
	info.SSL.Records = []api.DomainVerificationSSLRecord{}
	info.SSL.Pending = managed.GetState() == certificatemanagerpb.Certificate_ManagedCertificate_PROVISIONING

	dnsAuth, err := w.Client.GetDnsAuthorization(ctx, &certificatemanagerpb.GetDnsAuthorizationRequest{
		Name: w.dnsAuthName(d.ID),
	})
	if err != nil && !isNotFound(err) {
		return err
	}
	if dnsAuth != nil {
		if rec := dnsAuth.GetDnsResourceRecord(); rec != nil {
			info.SSL.DCV.Name = rec.GetName()
			info.SSL.DCV.Value = rec.GetData()
		}
	}

	if issue := managed.GetProvisioningIssue(); issue != nil && issue.GetDetails() != "" {
		info.SSL.Errors = append(info.SSL.Errors, issue.GetDetails())
	}
	for _, a := range managed.GetAuthorizationAttemptInfo() {
		if a.GetDetails() != "" {
			info.SSL.Errors = append(info.SSL.Errors, fmt.Sprintf("%s: %s", a.GetDomain(), a.GetDetails()))
		}
	}

	return w.setDomainVerification(ctx, d.ID, info)
}

func managedStateToDomainStatus(s certificatemanagerpb.Certificate_ManagedCertificate_State) api.DomainStatus {
	switch s {
	case certificatemanagerpb.Certificate_ManagedCertificate_ACTIVE:
		return api.DomainStatusSuccess
	case certificatemanagerpb.Certificate_ManagedCertificate_FAILED:
		return api.DomainStatusError
	default:
		// PROVISIONING and STATE_UNSPECIFIED both mean "keep waiting".
		return api.DomainStatusVerify
	}
}

func isNotFound(err error) bool {
	return status.Code(err) == codes.NotFound
}

func isAlreadyExists(err error) bool {
	return status.Code(err) == codes.AlreadyExists
}

// isPermanentCreateErr classifies errors that won't go away on retry and should
// short-circuit the row to DomainStatusError. Mirrors cloudflare-syncer's
// handling of 1407/1411/1461.
func isPermanentCreateErr(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	switch status.Code(err) {
	case codes.InvalidArgument, codes.FailedPrecondition, codes.OutOfRange:
		return true
	}
	return false
}
