package secretengine

import (
	"net/http"
	"reflect"
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
)

func TestRole_CreateSetsFields(t *testing.T) {
	tests := []struct {
		name       string
		create     map[string]any
		expectNorm map[string]any
	}{
		{
			name:   "username",
			create: map[string]any{"username": "test"},
		},
		{
			name:   "write_enabled",
			create: map[string]any{"username": "test", "write_enabled": true},
		},
		{
			name:   "description",
			create: map[string]any{"username": "test", "description": "a test role"},
		},
		{
			name:       "allowed_ips",
			create:     map[string]any{"username": "test", "allowed_ips": "1.1.1.1/32"},
			expectNorm: map[string]any{"allowed_ips": []string{"1.1.1.1/32"}},
		},
		{
			name:       "multiple allowed_ips",
			create:     map[string]any{"username": "test", "allowed_ips": "1.1.1.1/32,2.2.2.2/32"},
			expectNorm: map[string]any{"allowed_ips": []string{"1.1.1.1/32", "2.2.2.2/32"}},
		},
		{
			name:   "version",
			create: map[string]any{"username": "test", "version": 1},
		},
		{
			name:       "ttl",
			create:     map[string]any{"username": "test", "ttl": "1h"},
			expectNorm: map[string]any{"ttl": 1 * time.Hour},
		},
		{
			name:       "max_ttl",
			create:     map[string]any{"username": "test", "max_ttl": "3h"},
			expectNorm: map[string]any{"max_ttl": 3 * time.Hour},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, storage, _ := testBackendWithNetbox(t, netboxUserFound)

			// Write test data. Successful CREATEs apparently return nil,nil
			resp, err := b.HandleRequest(t.Context(), &logical.Request{
				Operation: logical.CreateOperation,
				Path:      "role/test",
				Data:      tt.create,
				Storage:   storage,
			})

			// 5xx error, vault broke
			if err != nil {
				t.Fatalf("CREATE /role/test returned err %v", err)
			}

			// 4xx error, bad user input
			if resp.IsError() {
				t.Fatalf("CREATE /role/test returned 4xx error, %v", resp.Error())
			}

			// Read it back
			resp, err = b.HandleRequest(t.Context(), &logical.Request{
				Operation: logical.ReadOperation,
				Path:      "role/test",
				Storage:   storage,
			})

			// 5xx error, vault broke
			if err != nil {
				t.Fatalf("READ /role/test returned err %v", err)
			}

			// 4xx error, bad user input
			if resp.IsError() {
				t.Fatalf("READ /role/test returned 4xx error, %v", resp.Error())
			}

			// Now the REAL tests...

			// Did we get back what we wrote?
			// Required fields
			if resp.Data["username"] != tt.create["username"] {
				t.Fatalf(`READ /role/test "username" validation failed, want: %s got %s`, tt.create["username"], resp.Data["username"])
			}

			// Loop over optional scalar fields
			for _, i := range []string{"write_enabled", "description", "version"} {
				if _, ok := tt.create[i]; ok {
					if _, ok = resp.Data[i]; ok {
						if tt.create[i] != resp.Data[i] {
							t.Errorf(`READ /role/test %q validation failed: wanted %v got %v`, i, tt.create[i], resp.Data[i])
						}
					} else {
						t.Errorf(`READ /role/test %q validation failed: field not found`, i)
					}
				}
			}

			// Loop over optional normalized fields and check the struct
			role, err := getRole(t.Context(), storage, "test")
			if err != nil {
				t.Fatalf("getRole returned an error: %v", err)
			}

			for _, i := range []string{"allowed_ips", "ttl", "max_ttl"} {
				if _, ok := tt.create[i]; ok {
					if _, ok = tt.expectNorm[i]; ok {
						switch i {
						case "allowed_ips":
							if !reflect.DeepEqual(role.AllowedIPs, tt.expectNorm[i]) {
								t.Errorf("role %q not set, want %v got %v", i, tt.expectNorm[i], role.AllowedIPs)
							}
						case "ttl":
							if role.TTL != tt.expectNorm[i] {
								t.Errorf("role %q not set, want %v got %v", i, tt.expectNorm[i], role.TTL)
							}
						case "max_ttl":
							if role.MaxTTL != tt.expectNorm[i] {
								t.Errorf("role %q not set, want %v got %v", i, tt.expectNorm[i], role.MaxTTL)
							}
						default:
							t.Fatalf("unhandled normalized field %q — add a switch case", i)
						}
					} else {
						t.Errorf(`test bug: no expectNorm for %q`, i)
					}
				}
			}
		})
	}
}

func TestRole_UpdateSetsFields(t *testing.T) {
	tests := []struct {
		name       string
		create     map[string]any
		update     map[string]any
		expectNorm map[string]any
	}{
		{
			name:   "username",
			create: map[string]any{"username": "test"},
			update: map[string]any{"username": "testuser"},
		},
		{
			name:   "write_enabled",
			create: map[string]any{"username": "test", "write_enabled": true},
			update: map[string]any{"write_enabled": false},
		},
		{
			name:   "description",
			create: map[string]any{"username": "test", "description": "a test role"},
			update: map[string]any{"description": "updated test role"},
		},
		{
			name:       "allowed_ips",
			create:     map[string]any{"username": "test", "allowed_ips": "1.1.1.1/32", "ttl": "1h"},
			update:     map[string]any{"allowed_ips": "2.2.2.2/32"},
			expectNorm: map[string]any{"allowed_ips": []string{"2.2.2.2/32"}, "ttl": 1 * time.Hour},
		},
		{
			name:       "multiple allowed_ips",
			create:     map[string]any{"username": "test", "allowed_ips": "1.1.1.1/32", "ttl": "1h"},
			update:     map[string]any{"allowed_ips": "2.2.2.2/32,3.3.3.3/32"},
			expectNorm: map[string]any{"allowed_ips": []string{"2.2.2.2/32", "3.3.3.3/32"}, "ttl": 1 * time.Hour},
		},
		{
			name:   "version",
			create: map[string]any{"username": "test", "version": 1},
			update: map[string]any{"version": 2},
		},
		{
			name:       "ttl",
			create:     map[string]any{"username": "test", "ttl": "1h"},
			update:     map[string]any{"ttl": "2h"},
			expectNorm: map[string]any{"ttl": 2 * time.Hour},
		},
		{
			name:       "max_ttl",
			create:     map[string]any{"username": "test", "ttl": "1h", "max_ttl": "3h"},
			update:     map[string]any{"max_ttl": "4h"},
			expectNorm: map[string]any{"max_ttl": 4 * time.Hour, "ttl": 1 * time.Hour},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, storage, _ := testBackendWithNetbox(t, netboxUserFound)

			// Write test data. Successful CREATEs apparently return nil,nil
			resp, err := b.HandleRequest(t.Context(), &logical.Request{
				Operation: logical.CreateOperation,
				Path:      "role/test",
				Data:      tt.create,
				Storage:   storage,
			})

			// 5xx error, vault broke
			if err != nil {
				t.Fatalf("CREATE /role/test returned err %v", err)
			}

			// 4xx error, bad user input
			if resp.IsError() {
				t.Fatalf("CREATE /role/test returned 4xx error, %v", resp.Error())
			}

			// Do an update
			resp, err = b.HandleRequest(t.Context(), &logical.Request{
				Operation: logical.UpdateOperation,
				Path:      "role/test",
				Data:      tt.update,
				Storage:   storage,
			})

			// 5xx error, vault broke
			if err != nil {
				t.Fatalf("UPDATE /role/test returned err %v", err)
			}

			// 4xx error, bad user input
			if resp.IsError() {
				t.Fatalf("UPDATE /role/test returned 4xx error, %v", resp.Error())
			}

			// Read it back
			resp, err = b.HandleRequest(t.Context(), &logical.Request{
				Operation: logical.ReadOperation,
				Path:      "role/test",
				Storage:   storage,
			})

			// 5xx error, vault broke
			if err != nil {
				t.Fatalf("READ /role/test returned err %v", err)
			}

			// 4xx error, bad user input
			if resp.IsError() {
				t.Fatalf("READ /role/test returned 4xx error, %v", resp.Error())
			}

			// Now the REAL tests...

			// Loop over all scalar fields
			for _, i := range []string{"username", "write_enabled", "description", "version"} {
				if _, ok := tt.update[i]; ok { // if it's in the update list, check that value
					if _, ok = resp.Data[i]; ok {
						if tt.update[i] != resp.Data[i] {
							t.Errorf(`READ /role/test %q update validation failed: wanted %v got %v`, i, tt.update[i], resp.Data[i])
						}
					} else {
						t.Errorf(`READ /role/test %q update validation failed: field not found`, i)
					}
				} else if _, ok := tt.create[i]; ok { // if it's not in the update list, is it in the create list?
					if _, ok = resp.Data[i]; ok {
						if tt.create[i] != resp.Data[i] {
							t.Errorf(`READ /role/test %q create validation failed: wanted %v got %v`, i, tt.create[i], resp.Data[i])
						}
					} else {
						t.Errorf(`READ /role/test %q create validation failed: field not found`, i)
					}
				}
			}

			// Loop over optional normalized fields and check the struct
			role, err := getRole(t.Context(), storage, "test")
			if err != nil {
				t.Fatalf("getRole returned an error: %v", err)
			}

			for _, i := range []string{"allowed_ips", "ttl", "max_ttl"} {
				_, inCreate := tt.create[i]
				_, inUpdate := tt.update[i]
				if inCreate || inUpdate {
					if _, ok := tt.expectNorm[i]; ok {
						switch i {
						case "allowed_ips":
							if !reflect.DeepEqual(role.AllowedIPs, tt.expectNorm[i]) {
								t.Errorf("role %q not set, want %v got %v", i, tt.expectNorm[i], role.AllowedIPs)
							}
						case "ttl":
							if role.TTL != tt.expectNorm[i] {
								t.Errorf("role %q not set, want %v got %v", i, tt.expectNorm[i], role.TTL)
							}
						case "max_ttl":
							if role.MaxTTL != tt.expectNorm[i] {
								t.Errorf("role %q not set, want %v got %v", i, tt.expectNorm[i], role.MaxTTL)
							}
						default:
							t.Fatalf("unhandled normalized field %q — add a switch case", i)
						}
					} else {
						t.Errorf(`test bug: no expectNorm for %q`, i)
					}
				}
			}
		})
	}
}

func TestRole_CreateFailsForMissingUsername(t *testing.T) {
	t.Skip("Not implemented")
}

func TestRole_CreateSetsDefaults(t *testing.T) {
	t.Skip("Not implemented")
}

func TestRole_ReadAfterDeleteReturnsNil(t *testing.T) {
	t.Skip("Not implemented")
}

func TestRole_DeleteIsIdempotent(t *testing.T) {
	t.Skip("Not implemented")
}

func TestRole_ReadReturnsNilWhenNotConfigured(t *testing.T) {
	t.Skip("Not implemented")
}

func TestRole_EnsureExistenceCheckWorks(t *testing.T) {
	t.Skip("Not implemented")
}

func TestRole_CreateValidatesUsername(t *testing.T) {
	var gotUser string
	hits := 0
	handler := func(w http.ResponseWriter, r *http.Request) {
		hits++
		gotUser = r.URL.Query().Get("username")
		netboxUserFound(w, r) // reuse the existing stub for the response body
	}

	b, storage, _ := testBackendWithNetbox(t, handler)

	// Write test data. Successful CREATEs apparently return nil,nil
	resp, err := b.HandleRequest(t.Context(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "role/test",
		Data:      map[string]any{"username": "test"},
		Storage:   storage,
	})

	// 5xx error, vault broke
	if err != nil {
		t.Fatalf("CREATE /role/test returned err %v", err)
	}

	// 4xx error, bad user input
	if resp.IsError() {
		t.Fatalf("CREATE /role/test returned 4xx error, %v", resp.Error())
	}

	if hits < 1 {
		t.Fatalf("CREATE /role/test didn't validate username")
	}

	if gotUser != "test" {
		t.Fatalf("CREATE /role/test validated wrong user, want %q, got %q", "test", gotUser)
	}
}

func TestRole_CreateWarnsForUnknownUser(t *testing.T) {
	b, storage, _ := testBackendWithNetbox(t, netboxNoUsers)

	// Write test data. Successful CREATEs apparently return nil,nil
	resp, err := b.HandleRequest(t.Context(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "role/test",
		Data:      map[string]any{"username": "test"},
		Storage:   storage,
	})

	// 5xx error, vault broke
	if err != nil {
		t.Fatalf("create returned err, %v", err)
	}

	// 4xx error, bad user input
	if resp.IsError() {
		t.Fatalf("create failed, %v", resp.Error())
	}

	// Expect warning `User "test" not found in netbox. Be sure to configure your user befor minting tokens.`
	assertSingleWarning(t, resp, `"test" not a valid`)

	// Validate role was actually written
	role, err := getRole(t.Context(), storage, "test")
	if err != nil {
		t.Fatalf("getRole after warn returned err: %v", err)
	}

	if role == nil {
		t.Fatalf("role was not persisted despite warning")
	}

	if role.Username != "test" {
		t.Fatalf("persisted username = %q, want %q", role.Username, "test")
	}

}

func TestRole_CreateWarnsWhenNetboxUnreachable(t *testing.T) {
	b, storage, srv := testBackendWithNetbox(t, netboxNoUsers)
	srv.Close()

	// Write test data
	resp, err := b.HandleRequest(t.Context(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "role/test",
		Data:      map[string]any{"username": "test"},
		Storage:   storage,
	})

	// 5xx error, vault broke
	if err != nil {
		t.Fatalf("create returned err, %v", err)
	}

	// 4xx error, bad user input
	if resp.IsError() {
		t.Fatalf("create failed, %v", resp.Error())
	}

	// Expect warning `Unable to validate username because netbox was unreachable`
	assertSingleWarning(t, resp, `netbox was unreachable`)

	// Validate role was actually written
	role, err := getRole(t.Context(), storage, "test")
	if err != nil {
		t.Fatalf("getRole after warn returned err: %v", err)
	}

	if role == nil {
		t.Fatalf("role was not persisted despite warning")
	}

	if role.Username != "test" {
		t.Fatalf("persisted username = %q, want %q", role.Username, "test")
	}
}

func TestRole_CreateWarnsWhenNotConfigured(t *testing.T) {
	b, storage := testBackend(t)

	// Write test data
	resp, err := b.HandleRequest(t.Context(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "role/test",
		Data:      map[string]any{"username": "test"},
		Storage:   storage,
	})

	// 5xx error, vault broke
	if err != nil {
		t.Fatalf("create returned err, %v", err)
	}

	// 4xx error, bad user input
	if resp.IsError() {
		t.Fatalf("create failed, %v", resp.Error())
	}

	// Expect warning `Netbox backend not configured. Be sure to write to /config before minting tokens.`
	assertSingleWarning(t, resp, `not configured`)

	// Validate role was actually written
	role, err := getRole(t.Context(), storage, "test")
	if err != nil {
		t.Fatalf("getRole after warn returned err: %v", err)
	}

	if role == nil {
		t.Fatalf("role was not persisted despite warning")
	}

	if role.Username != "test" {
		t.Fatalf("persisted username = %q, want %q", role.Username, "test")
	}
}

func TestRole_CreateInvalidIPsFails(t *testing.T) {
	t.Skip("Not implemented")
}

func TestRole_CreateRejectsInvalidTokenVersion(t *testing.T) {
	t.Skip("Not implemented")
}

func TestRole_ListReturnsRoleNames(t *testing.T) {
	t.Skip("Not implemented")
}

func TestRole_ListReturnsEmptyWhenNoRoles(t *testing.T) {
	t.Skip("Not implemented")
}

func TestFuncValidateAllowedIP_ValidIPsReturnNoError(t *testing.T) {
	tests := []struct {
		name string
		ip   string
	}{
		{"ip4", "1.1.1.1/32"},
		{"network4", "192.168.5.0/24"},
		{"network6", "2001:0db8::/32"},
		{"ip6", "fe80::ce4:41ff:fe6e:5065/128"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateAllowedIP(tt.ip)
			if err != nil {
				t.Fatalf("validateAllowedIP() returned err: %v", err)
			}
		})
	}
}

func TestFuncValidateAllowedIP_InvalidIPsReturnError(t *testing.T) {
	tests := []struct {
		name string
		ip   string
	}{
		{"ip4 missing mask", "1.1.1.1"},
		{"network4 host bits set", "192.168.5.5/24"},
		{"ip6 missing mask", "2600::"},
		{"network6 host bits set", "fe80::ce4:41ff:fe6e:5065/64"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateAllowedIP(tt.ip)
			if err == nil {
				t.Fatalf("validateAllowedIP() did not return error")
			}
		})
	}
}
