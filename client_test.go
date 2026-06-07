package secretengine

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestResolveUserID(t *testing.T) {
	tests := []struct {
		name           string
		username       string
		netboxResponse string
		wantID         int
		wantErr        bool
	}{
		{"happy", "automation", `{"count":1,"results":[{"id":42,"username":"automation"}]}`, 42, false},
		{"too many", "automation", `{"count":2,"results":[{"id":42,"username":"automation"}]}`, -1, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// A stand-in NetBox that always returns one user.
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.Write([]byte(tt.netboxResponse))
			}))
			defer srv.Close()

			client, err := newClient(&netboxConfig{URL: srv.URL, Token: "test"})
			if err != nil {
				t.Fatalf("newClient returned error: %v", err)
			}

			id, err := client.resolveUserID(context.Background(), tt.username)
			if (err != nil) != tt.wantErr {
				t.Errorf("resolveUserID(%s): want error: %t, got error: %t", tt.username, tt.wantErr, (err != nil))
			} else if id != tt.wantID {
				t.Errorf("resolveUserID(%s): want: %d, got: %d", tt.username, tt.wantID, id)
			}
		})
	}

}
