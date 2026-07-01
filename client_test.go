// Copyright Landy Bible <landy@ljb2of3.net> 2026
// SPDX-License-Identifier: MPL-2.0

package secretengine

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestClient_ResolveUserID(t *testing.T) {
	tests := []struct {
		name        string
		username    string
		simResponse string
		simStatus   int
		wantID      int
		wantErr     error
		breakServer bool
	}{
		{
			name:        "happy",
			username:    "automation",
			simResponse: `{"count":1,"results":[{"id":42,"username":"automation"}]}`,
			wantID:      42,
		},
		{
			name:        "no results",
			username:    "automation",
			simResponse: `{"count":0,"results":[]}`,
			wantErr:     errUserNotFound,
		},
		{
			name:        "netbox malformed",
			username:    "automation",
			simResponse: `{"count":1,"results":[]}`,
			wantErr:     errUnexpectedNumResults,
		},
		{
			name:        "data malformed",
			username:    "automation",
			simResponse: `{"count":q,"results":[]}`,
			wantErr:     errInvalidResponseBody,
		},
		{
			name:        "json malformed",
			username:    "automation",
			simResponse: `{"count":0,"results":[}`,
			wantErr:     errInvalidResponseBody,
		},
		{
			name:        "too many",
			username:    "automation",
			simResponse: `{"count":2,"results":[{"id":42,"username":"automation"}]}`,
			wantErr:     errUnexpectedNumResults,
		},
		{
			name:        "wrong user",
			username:    "automation",
			simResponse: `{"count":1,"results":[{"id":55,"username":"other-user"}]}`,
			wantErr:     errWrongUser,
		},
		{
			name:      "500 error",
			username:  "automation",
			simStatus: 500,
			wantErr:   errUnexpectedStatus,
		},
		{
			name:      "403 error",
			username:  "automation",
			simStatus: 403,
			wantErr:   errUnexpectedStatus,
		},
		{
			name:        "case difference",
			username:    "AUTOMATION",
			simResponse: `{"count":1,"results":[{"id":42,"username":"automation"}]}`,
			wantID:      42,
		},
		{
			name:        "transport failure",
			breakServer: true,
			wantErr:     errRequestFailure,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if !strings.HasPrefix(r.URL.Path, "/api/users/users/") {
					t.Errorf("got %q, want /api/users/users/", r.URL.Path)
				}
				w.Header().Set("Content-Type", "application/json")
				if tt.simStatus != 0 {
					w.WriteHeader(tt.simStatus)
				}
				w.Write([]byte(tt.simResponse))
			}))
			defer srv.Close()

			if tt.breakServer {
				srv.Close()
			}

			client, err := newClient(&netboxConfig{URL: srv.URL, Token: "test"})
			if err != nil {
				t.Fatalf("newClient returned error: %v", err)
			}

			id, err := client.resolveUserID(context.Background(), tt.username)

			if !errors.Is(err, tt.wantErr) {
				t.Errorf("resolveUserID(%s): want error: %v, got error: %v", tt.username, tt.wantErr, err)
			}
			if tt.wantErr == nil && id != tt.wantID {
				t.Errorf("resolveUserID(%s): want: %d, got: %d", tt.username, tt.wantID, id)
			}
		})
	}

}

func TestClient_GetVersionContract(t *testing.T) {

	tests := []struct {
		name         string
		simResponse  string
		simStatus    int
		wantContract tokenContract
		wantErr      error
		breakServer  bool
	}{
		{
			name:         "old contract",
			simResponse:  `{"netbox-version": "3.7.8"}`,
			wantContract: oldContract,
			wantErr:      nil,
		},
		{
			name:         "old contract boundary",
			simResponse:  `{"netbox-version": "4.4.10"}`,
			wantContract: oldContract,
			wantErr:      nil,
		},
		{
			name:         "partial new contract boundary",
			simResponse:  `{"netbox-version": "4.5.0"}`,
			wantContract: newContractNoV2,
			wantErr:      nil,
		},
		{
			name:         "partial new contract2",
			simResponse:  `{"netbox-version": "4.6.0"}`,
			wantContract: newContractNoV2,
			wantErr:      nil,
		},
		{
			name:         "fully working new contract boundary",
			simResponse:  `{"netbox-version": "4.6.1"}`,
			wantContract: newContract,
			wantErr:      nil,
		},
		{
			name:         "fully working new contract",
			simResponse:  `{"netbox-version": "4.6.2"}`,
			wantContract: newContract,
			wantErr:      nil,
		},
		{
			name:         "missing version",
			simResponse:  `{}`,
			wantContract: unknownContract,
			wantErr:      errUnknownContract,
		},
		{
			name:         "malformed version",
			simResponse:  `{"netbox-version": "broken"}`,
			wantContract: unknownContract,
			wantErr:      errUnknownContract,
		},
		{
			name:         "malformed json",
			simResponse:  `{"netbox-version" "4.0.0"}`,
			wantContract: unknownContract,
			wantErr:      errInvalidResponseBody,
		},
		{
			name:         "server error",
			simStatus:    500,
			wantContract: unknownContract,
			wantErr:      errUnexpectedStatus,
		},
		{
			name:      "auth failure",
			simStatus: 403,
			wantErr:   errUnexpectedStatus,
		},
		{
			name:        "transport failure",
			wantErr:     errRequestFailure,
			breakServer: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/api/status/" {
					t.Errorf("got path %q, want /api/status/", r.URL.Path)
				}
				w.Header().Set("Content-Type", "application/json")
				if tt.simStatus != 0 {
					w.WriteHeader(tt.simStatus)
				}
				w.Write([]byte(tt.simResponse))
			}))
			defer srv.Close()

			if tt.breakServer {
				srv.Close()
			}

			client, err := newClient(&netboxConfig{URL: srv.URL, Token: "test"})
			if err != nil {
				t.Fatalf("got %v, want nil", err)
			}

			contract, err := client.getTokenContract(context.Background())

			if !errors.Is(err, tt.wantErr) {
				t.Errorf("got %v, want %v", err, tt.wantErr)
			}
			if contract != tt.wantContract {
				t.Errorf("got %v, want %v", contract, tt.wantContract)
			}
		})
	}
}

func TestClient_RenewRequiresKey(t *testing.T) {
	tests := []struct {
		name        string
		simResponse string
		simStatus   int
		want        bool
		wantErr     error
		breakServer bool
	}{
		{
			name:        "yes 3.x",
			simResponse: `{"netbox-version": "3.7.8"}`,
			want:        true,
			wantErr:     nil,
		},
		{
			name:        "yes 4.x",
			simResponse: `{"netbox-version": "4.0.9"}`,
			want:        true,
			wantErr:     nil,
		},
		{
			name:        "no",
			simResponse: `{"netbox-version": "4.0.10"}`,
			want:        false,
			wantErr:     nil,
		},
		{
			name:        "missing version",
			simResponse: `{}`,
			wantErr:     errUnknownContract,
		},
		{
			name:        "malformed version",
			simResponse: `{"netbox-version": "broken"}`,
			wantErr:     errUnknownContract,
		},
		{
			name:        "malformed json",
			simResponse: `{"netbox-version" "4.0.0"}`,
			wantErr:     errInvalidResponseBody,
		},
		{
			name:      "server error",
			simStatus: 500,
			wantErr:   errUnexpectedStatus,
		},
		{
			name:      "auth failure",
			simStatus: 403,
			wantErr:   errUnexpectedStatus,
		},
		{
			name:        "transport failure",
			wantErr:     errRequestFailure,
			breakServer: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/api/status/" {
					t.Errorf("got path %q, want /api/status/", r.URL.Path)
				}
				w.Header().Set("Content-Type", "application/json")
				if tt.simStatus != 0 {
					w.WriteHeader(tt.simStatus)
				}
				w.Write([]byte(tt.simResponse))
			}))
			defer srv.Close()

			if tt.breakServer {
				srv.Close()
			}

			client, err := newClient(&netboxConfig{URL: srv.URL, Token: "test"})
			if err != nil {
				t.Fatalf("got %v, want nil", err)
			}

			got, err := client.renewRequiresKey(context.Background())

			if !errors.Is(err, tt.wantErr) {
				t.Errorf("got %v, want %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}
