// Copyright Landy Bible <landy@ljb2of3.net> 2026
// SPDX-License-Identifier: MPL-2.0

package secretengine

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestResolveUserID(t *testing.T) {
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
			// A stand-in NetBox that always returns one user.
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
