package secretengine

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
)

// Asserts that we received a fatal error
func assertFatal(t *testing.T, resp *logical.Response, err error) {
	t.Helper()
	if err == nil {
		t.Fatalf("want fatal err, got nil (resp=%v)", resp)
	}
}

// Asserts that we did not receive an fatal error
func assertNotFatal(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("want nil, got fatal err: %v", err)
	}
}

func assertOK(t *testing.T, resp *logical.Response, err error) {
	t.Helper()
	assertNotFatal(t, err)
	if resp.IsError() {
		t.Fatalf("want nil, got resp.ErrorResponse: %v", resp.Error())
	}
}

// Asserts that resp.IsError() is true and that the error message contains a given string
func assertError(t *testing.T, resp *logical.Response, err error, mustContain string) {
	t.Helper()
	assertNotFatal(t, err)
	if resp == nil || !resp.IsError() {
		t.Fatalf("expected a user error, got resp=%v", resp)
	}
	if msg := resp.Error().Error(); !strings.Contains(strings.ToLower(msg), strings.ToLower(mustContain)) {
		t.Fatalf("user error %q did not mention %q", msg, mustContain)
	}
}

// Asserts that len(resp.Warnings) == 1 and that the warning message contains a given string
func assertSingleWarning(t *testing.T, resp *logical.Response, err error, mustContain string) {
	t.Helper()

	assertOK(t, resp, err)

	if resp == nil {
		t.Fatalf("got nil, want resp")
	}

	// We expect exactly one warning
	if len(resp.Warnings) != 1 {
		t.Fatalf("got %d warnings, want 1: %q", len(resp.Warnings), resp.Warnings)
	}

	if !strings.Contains(strings.ToLower(resp.Warnings[0]), strings.ToLower(mustContain)) {
		t.Fatalf("%q not in warning, got %q", mustContain, resp.Warnings[0])
	}
}

func assertDefault(t *testing.T, resp *logical.Response, field string, value any) {
	t.Helper()
	if !reflect.DeepEqual(resp.Data[field], value) {
		t.Fatalf(`create didn't set default for %q: wanted %v, got %v`, field, value, resp.Data[field])
	}
}

func assertListKeys(t *testing.T, resp *logical.Response, want []string) {
	t.Helper()
	data, ok := resp.Data["keys"]
	if !ok {
		t.Fatalf("want keys, got none")
	}
	if keys := data.([]string); !reflect.DeepEqual(keys, want) {
		t.Fatalf("want %v, got %v", want, keys)
	}
}

func assertEqual(t *testing.T, want any, got any) {
	t.Helper()
	if !reflect.DeepEqual(want, got) {
		t.Fatalf("want %v, got %v", want, got)
	}
}

func assertExpireTime(t *testing.T, body map[string]any, ttl time.Duration) {
	if _, ok := body["expires"]; ok {

	} else {
		t.Fatalf("expire time not set")
	}

	t.Error("not implemented")
}
