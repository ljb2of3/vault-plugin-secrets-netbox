// Copyright Landy Bible <landy@ljb2of3.net> 2026
// SPDX-License-Identifier: MPL-2.0

package secretengine

import (
	"net/http"
	"reflect"
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
)

func TestRole_CreateOKSetsFields(t *testing.T) {
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
			name:   "version 2",
			create: map[string]any{"username": "test", "version": 2},
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
			backend, storage, _ := testBackendWithNetbox(t, netboxUserFound)

			// Write test data. Successful CREATEs apparently return nil,nil
			resp, err := roleCreate(t, backend, storage, "test", tt.create)

			assertOK(t, resp, err)

			// Read it back
			resp, err = roleRead(t, backend, storage, "test")

			assertOK(t, resp, err)

			// Now the REAL tests...

			// Did we get back what we wrote?
			// Required fields
			if resp.Data["username"] != tt.create["username"] {
				t.Fatalf(`READ /role/test "username" validation failed, want: %s got %s`, tt.create["username"], resp.Data["username"])
			}

			// Loop over optional scalar fields
			for _, i := range []string{"write_enabled", "version"} {
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

func TestRole_UpdateOKSetsFields(t *testing.T) {
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
			create: map[string]any{"username": "test"}, // defaults to v1
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
			backend, storage, _ := testBackendWithNetbox(t, netboxUserFound)

			// Create a role
			resp, err := roleCreate(t, backend, storage, "test", tt.create)

			assertOK(t, resp, err)

			// Do an update
			resp, err = roleUpdate(t, backend, storage, "test", tt.update)

			assertOK(t, resp, err)

			// Read it back
			resp, err = roleRead(t, backend, storage, "test")

			assertOK(t, resp, err)

			// Now the REAL tests...

			// Loop over all scalar fields
			for _, i := range []string{"username", "write_enabled", "version"} {
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

func TestRole_CreateErrorForMissingUsername(t *testing.T) {
	backend, storage := testBackend(t)

	resp, err := roleCreate(t, backend, storage, "test", map[string]any{"write_enabled": true})

	assertError(t, resp, err, "username")
}

func TestRole_CreateOKSetsDefaults(t *testing.T) {
	// Create mock backend
	backend, storage, _ := testBackendWithNetbox(t, netboxUserFound)

	// Write test role
	resp, err := roleCreateDefault(t, backend, storage)
	assertOK(t, resp, err)

	// Read test role
	resp, err = roleRead(t, backend, storage, "test")
	assertOK(t, resp, err)

	// Assert all default values were set as expected
	assertDefault(t, resp, "write_enabled", false)
	assertDefault(t, resp, "version", 1)
	assertDefault(t, resp, "allowed_ips", []string{})
	assertDefault(t, resp, "ttl", float64(0))
	assertDefault(t, resp, "max_ttl", float64(0))
}

func TestRole_ReadAfterDeleteReturnsNil(t *testing.T) {
	// Create mock backend
	backend, storage, _ := testBackendWithNetbox(t, netboxUserFound)

	// Write test role
	resp, err := roleCreateDefault(t, backend, storage)
	assertOK(t, resp, err)

	// Delete test role
	resp, err = roleDelete(t, backend, storage, "test")
	assertOK(t, resp, err)

	// Read test role
	resp, err = roleRead(t, backend, storage, "test")
	assertOK(t, resp, err)

	// Assert read returned nil
	if resp != nil {
		t.Fatalf("got %v, want nil", resp)
	}
}

func TestRole_DeleteIsIdempotent(t *testing.T) {
	// Create mock backend
	backend, storage, _ := testBackendWithNetbox(t, netboxUserFound)

	// Write a test role
	resp, err := roleCreateDefault(t, backend, storage)
	assertOK(t, resp, err)

	// Delete test role
	resp, err = roleDelete(t, backend, storage, "test")
	assertOK(t, resp, err)

	// Delete the role a second time
	resp, err = roleDelete(t, backend, storage, "test")
	assertOK(t, resp, err)
}

func TestRole_ReadReturnsNilWhenNotExists(t *testing.T) {
	// Create mock backend
	backend, storage := testBackend(t)

	// Read a role that doesn't exist
	resp, err := roleRead(t, backend, storage, "test")
	assertOK(t, resp, err)

	// Assert we actually got nil
	if resp != nil {
		t.Fatalf("got %v, want nil", resp)
	}
}

func TestRole_EnsureExistenceCheckWorks(t *testing.T) {
	// Create mock backend
	backend, storage := testBackend(t)

	// Check to see if test role exists
	_, exists, err := backend.HandleExistenceCheck(t.Context(), &logical.Request{
		Operation: logical.CreateOperation, Path: "role/test", Storage: storage,
	})

	// Assert that the role does not exist
	if err != nil {
		t.Fatalf("existence check returned err: %v", err)
	}

	if exists {
		t.Fatalf("role exists before create")
	}

	// Create test role
	resp, err := roleCreateDefault(t, backend, storage)
	assertOK(t, resp, err)

	// Chceck again to see if role exists
	_, exists, err = backend.HandleExistenceCheck(t.Context(), &logical.Request{
		Operation: logical.CreateOperation, Path: "role/test", Storage: storage,
	})

	// Assert that the role exists
	if err != nil {
		t.Fatalf("existence check returned err: %v", err)
	}

	if !exists {
		t.Fatalf("role does not exist after create")
	}
}

func TestRole_CreateOKValidatesUsername(t *testing.T) {
	// Create backend handler we can watch
	var gotUser string
	var hits int
	handler := func(w http.ResponseWriter, r *http.Request) {
		hits++
		gotUser = r.URL.Query().Get("username")
		netboxUserFound(w, r) // reuse the existing stub for the response body
	}

	// Create mock backend with special handler
	backend, storage, _ := testBackendWithNetbox(t, handler)

	// Write test role
	resp, err := roleCreateDefault(t, backend, storage)
	assertOK(t, resp, err)

	// Assert create actually hit the backend to validate the username
	if hits < 1 {
		t.Fatalf("CREATE /role/test didn't validate username")
	}

	// Assert create validated the correct username
	if gotUser != "test" {
		t.Fatalf("CREATE /role/test validated wrong user, want %q, got %q", "test", gotUser)
	}
}

func TestRole_CreateWarnForUnknownUser(t *testing.T) {
	// Create mock backend that returns no users
	backend, storage, _ := testBackendWithNetbox(t, netboxNoUsers)

	// Write test role
	resp, err := roleCreateDefault(t, backend, storage)

	// Assert we got a warning for the invalid user
	assertWarning(t, resp, err, "not a valid")

	// Assert role was actually written
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

func TestRole_CreateWarnWhenNetboxUnreachable(t *testing.T) {
	// Create mock backend
	backend, storage, srv := testBackendWithNetbox(t, netboxNoUsers)

	// Shut down the backend
	srv.Close()

	// Create test role
	resp, err := roleCreateDefault(t, backend, storage)

	// Assert we got a warning about netbox being unreachable
	assertWarning(t, resp, err, "netbox was unreachable")

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

func TestRole_CreateWarnWhenNotConfigured(t *testing.T) {
	// Create mock backend without netbox
	backend, storage := testBackend(t)

	// Write test role
	resp, err := roleCreateDefault(t, backend, storage)

	// Expect warning `Netbox backend not configured. Be sure to write to /config before minting tokens.`
	assertWarning(t, resp, err, "not configured")

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

func TestRole_CreateErrorForMissingCIDR(t *testing.T) {
	// Create mock backend
	backend, storage := testBackend(t)

	// Create test role with invalid IP
	resp, err := roleCreate(t, backend, storage, "test", map[string]any{"username": "test", "allowed_ips": "1.1.1.1"})

	// Assert we got an error about the missing cidr mask
	assertError(t, resp, err, "invalid cidr address")
}

func TestRole_CreateErrorForHostBits(t *testing.T) {
	// Create mock backend
	backend, storage := testBackend(t)

	// Create test role with invalid IP
	resp, err := roleCreate(t, backend, storage, "test", map[string]any{"username": "test", "allowed_ips": "1.1.1.1/24"})

	// Assert we got an error about the host bits being set
	assertError(t, resp, err, "host bits")
}

func TestRole_CreateErrorForInvalidTokenVersion(t *testing.T) {
	// Create mock backend
	backend, storage := testBackend(t)

	// Create test role with invalid token version
	resp, err := roleCreate(t, backend, storage, "test", map[string]any{"username": "test", "version": 3})

	// Assert we got an error about the wrong token version
	assertError(t, resp, err, "version must")
}

func TestRole_ListReturnsRoleNames(t *testing.T) {
	// Create mock backend
	backend, storage, _ := testBackendWithNetbox(t, netboxUserFound)

	// Write test role
	resp, err := roleCreateDefault(t, backend, storage)
	assertOK(t, resp, err)

	// List roles
	resp, err = roleList(t, backend, storage)
	assertOK(t, resp, err)

	// Assert role is listed
	assertListKeys(t, resp, []string{"test"})
}

func TestRole_ListReturnsEmptyWhenNoRoles(t *testing.T) {
	// Create mock backend
	backend, storage := testBackend(t)

	// List roles
	resp, err := roleList(t, backend, storage)
	assertOK(t, resp, err)

	// Assert we got nothing back
	if _, ok := resp.Data["keys"]; ok {
		t.Fatalf("want false, got true")
	}
}

func TestRole_ListReturnsMultipleSorted(t *testing.T) {
	// Create mock backend
	backend, storage, _ := testBackendWithNetbox(t, netboxUserFound)

	// Write three roles
	resp, err := roleCreate(t, backend, storage, "c", map[string]any{"username": "a"})
	assertOK(t, resp, err)

	resp, err = roleCreate(t, backend, storage, "a", map[string]any{"username": "a"})
	assertOK(t, resp, err)

	resp, err = roleCreate(t, backend, storage, "b", map[string]any{"username": "b"})
	assertOK(t, resp, err)

	// List roles
	resp, err = roleList(t, backend, storage)
	assertOK(t, resp, err)

	// Assert roles are sorted
	assertListKeys(t, resp, []string{"a", "b", "c"})
}

func TestRole_ListExcludesDeletedRole(t *testing.T) {
	// Create mock backend
	backend, storage, _ := testBackendWithNetbox(t, netboxUserFound)

	// Write two roles
	resp, err := roleCreate(t, backend, storage, "a", map[string]any{"username": "a"})
	assertOK(t, resp, err)

	resp, err = roleCreate(t, backend, storage, "b", map[string]any{"username": "b"})
	assertOK(t, resp, err)

	// Delete role b
	resp, err = roleDelete(t, backend, storage, "b")
	assertOK(t, resp, err)

	// List roles
	resp, err = roleList(t, backend, storage)
	assertOK(t, resp, err)

	// Assert that b doesn't show up in the list
	assertListKeys(t, resp, []string{"a"})
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

func TestRole_UpdateFatalWhenRoleMissing(t *testing.T) {
	// Create mock backend
	backend, storage := testBackend(t)

	// Update the config without creating it
	resp, err := roleUpdate(t, backend, storage, "test", map[string]any{})

	// Assert that this is fatal
	assertFatal(t, resp, err, "not found during update")
}

func TestRole_CreateErrorForVersion0(t *testing.T) {
	// Create mock backend
	backend, storage, _ := testBackendWithNetbox(t, netboxUserFound)

	// Write the role with the now-invalid version 0 (auto was dropped)
	resp, err := roleCreate(t, backend, storage, "test", map[string]any{"username": "test", "version": 0})
	assertError(t, resp, err, "version must")
}
