package main

import (
	"errors"
	"testing"

	"cloud.google.com/go/certificatemanager/apiv1/certificatemanagerpb"
	"github.com/deploys-app/api"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// TestManagedStateToDomainStatus pins the GCP managed-certificate state -> domain
// status mapping that drives what users see: only ACTIVE is Success and only
// FAILED is Error; every other state (PROVISIONING, STATE_UNSPECIFIED, and any
// future/unknown value) must stay in Verify ("keep waiting") rather than wrongly
// flip a still-provisioning cert to Success or Error.
func TestManagedStateToDomainStatus(t *testing.T) {
	tests := []struct {
		state certificatemanagerpb.Certificate_ManagedCertificate_State
		want  api.DomainStatus
	}{
		{certificatemanagerpb.Certificate_ManagedCertificate_ACTIVE, api.DomainStatusSuccess},
		{certificatemanagerpb.Certificate_ManagedCertificate_FAILED, api.DomainStatusError},
		{certificatemanagerpb.Certificate_ManagedCertificate_PROVISIONING, api.DomainStatusVerify},
		{certificatemanagerpb.Certificate_ManagedCertificate_STATE_UNSPECIFIED, api.DomainStatusVerify},
	}
	for _, tc := range tests {
		if got := managedStateToDomainStatus(tc.state); got != tc.want {
			t.Errorf("managedStateToDomainStatus(%v) = %v, want %v", tc.state, got, tc.want)
		}
	}
}

// TestIsNotFoundIsAlreadyExists pins the gRPC error classifiers the reconcile
// relies on for idempotency: AlreadyExists is treated as "create succeeded
// earlier" and NotFound as "nothing to do". They must key off the gRPC status
// code only — a nil error or a non-gRPC error is neither.
func TestIsNotFoundIsAlreadyExists(t *testing.T) {
	tests := []struct {
		name           string
		err            error
		wantNotFound   bool
		wantAlreadyHas bool
	}{
		{"NotFound", status.Error(codes.NotFound, "x"), true, false},
		{"AlreadyExists", status.Error(codes.AlreadyExists, "x"), false, true},
		{"other gRPC code", status.Error(codes.Internal, "x"), false, false},
		{"nil", nil, false, false},
		{"plain error", errors.New("boom"), false, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := isNotFound(tc.err); got != tc.wantNotFound {
				t.Errorf("isNotFound(%v) = %v, want %v", tc.err, got, tc.wantNotFound)
			}
			if got := isAlreadyExists(tc.err); got != tc.wantAlreadyHas {
				t.Errorf("isAlreadyExists(%v) = %v, want %v", tc.err, got, tc.wantAlreadyHas)
			}
		})
	}
}
