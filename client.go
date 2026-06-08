package secretengine

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
)

type netboxClient struct {
	baseURL     string
	token       string
	httpClient  *http.Client
	tokenScheme string
}

func (b *netboxBackend) getClient(ctx context.Context, s logical.Storage) (*netboxClient, error) {
	// Return an existing client, if possible.
	// We only need a read lock for this.
	b.lock.RLock()
	if b.client != nil {
		defer b.lock.RUnlock()
		return b.client, nil
	}

	// No existing client, so we'll have to build one.
	// Drop the read lock and get a write lock instead.
	b.lock.RUnlock()
	b.lock.Lock()
	defer b.lock.Unlock()

	// Another goroutine may have build the client while we waited for our write lock
	// so we'll try one more time to return an existing client
	if b.client != nil {
		return b.client, nil
	}

	// Nope, we're really going to have to do this
	// Grab our config
	config, err := getConfig(ctx, s)
	if err != nil {
		return nil, err
	}

	// Check if our config is empty
	if config == nil {
		return nil, errors.New("netbox backend not configured")
	}

	// All good, create a client from our config
	client, err := newClient(config)
	if err != nil {
		return nil, err
	}

	// Store our client on the backend, and return it
	b.client = client
	return b.client, nil
}

func newClient(config *netboxConfig) (*netboxClient, error) {
	// Disable TLS verification if requested
	tlsConfig := &tls.Config{InsecureSkipVerify: config.InsecureTLS}

	// Import the CA cert, if configured
	if config.CACert != "" {
		pool := x509.NewCertPool()
		if ok := pool.AppendCertsFromPEM([]byte(config.CACert)); !ok {
			return nil, errors.New("failed to parse ca_cert PEM")
		}
		tlsConfig.RootCAs = pool
	}

	// Config is all good, build our client
	return &netboxClient{
		baseURL: strings.TrimRight(config.URL, "/"),
		token:   config.Token,
		httpClient: &http.Client{
			Timeout:   30 * time.Second,
			Transport: &http.Transport{TLSClientConfig: tlsConfig},
		},
		tokenScheme: config.TokenScheme,
	}, nil
}

func (c *netboxClient) rawRequest(ctx context.Context, method string, path string, body any) (*http.Response, error) {
	// JSON encode the body
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", errBuildingRequest, err)
		}

		reader = bytes.NewReader(encoded)
	}

	// Construct request
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reader)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errBuildingRequest, err)
	}

	// Set the auth header
	if c.tokenScheme == "v2" || (c.tokenScheme == "auto" && strings.HasPrefix(c.token, "nbt_")) {
		// Netbox v2 token
		req.Header.Set("Authorization", strings.Join([]string{"Bearer", c.token}, " "))
	} else {
		// Netbox v1 token
		req.Header.Set("Authorization", strings.Join([]string{"Token", c.token}, " "))
	}

	// And the content type if required
	if reader != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	// Annnd the accept header
	req.Header.Set("Accept", "application/json")

	// Fire the request
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errRequestFailure, err)
	}

	return resp, nil
}

func (c *netboxClient) doRequest(ctx context.Context, method string, path string, input any, output any) error {
	resp, err := c.rawRequest(ctx, method, path, input)
	if err != nil {
		return err
	}

	// Close the body when we exit the func
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("%w: %d %s", errUnexpectedStatus, resp.StatusCode, http.StatusText(resp.StatusCode))
	}

	if output != nil {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("%w: %w", errReadingResponse, err)
		}

		err = json.Unmarshal(body, output)
		if err != nil {
			return fmt.Errorf("%w: %w", errInvalidResponseBody, err)
		}
	} else {
		_, _ = io.Copy(io.Discard, resp.Body)
	}

	return nil
}

func (c *netboxClient) resolveUserID(ctx context.Context, username string) (int, error) {
	data := struct {
		Count   int `json:"count"`
		Results []struct {
			ID       int    `json:"id"`
			Username string `json:"username"`
		} `json:"results"`
	}{}

	err := c.doRequest(ctx, "GET", "/api/users/users/?username="+url.QueryEscape(username), nil, &data)
	if err != nil {
		return 0, err
	}

	if data.Count == 0 {
		return 0, errUserNotFound
	}

	if data.Count > 1 {
		return 0, errUnexpectedNumResults
	}

	if len(data.Results) != 1 {
		return 0, errUnexpectedNumResults
	}

	if !strings.EqualFold(data.Results[0].Username, username) {
		return 0, errWrongUser
	}

	return data.Results[0].ID, nil
}

var (
	errBuildingRequest      = errors.New("bad request")
	errRequestFailure       = errors.New("request failure")
	errUnexpectedStatus     = errors.New("unexpected status code")
	errReadingResponse      = errors.New("reading response body")
	errInvalidResponseBody  = errors.New("invalid response body")
	errUserNotFound         = errors.New("user not found")
	errUnexpectedNumResults = errors.New("unexpected number of results")
	errWrongUser            = errors.New("query returned wrong user")
)
