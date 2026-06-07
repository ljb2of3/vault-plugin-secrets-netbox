package secretengine

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
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

func (c *netboxClient) doRequest(ctx context.Context, method string, path string, body any) (*http.Response, error) {
	// JSON encode the body
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}

		reader = bytes.NewReader(encoded)
	}

	// Construct request
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reader)
	if err != nil {
		return nil, err
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
		return nil, err
	}

	return resp, nil
}

func (c *netboxClient) resolveUserID(ctx context.Context, username string) (int, error) {
	resp, err := c.doRequest(ctx, "GET", "/api/users/users/?username="+url.QueryEscape(username), nil)
	if err != nil {
		return -1, err
	}

	// Close the body when we exit the func
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return -1, errors.New("unable to fetch user id: " + http.StatusText(resp.StatusCode))
	}

	data := struct {
		Count   int `json:"count"`
		Results []struct {
			ID       int    `json:"id"`
			Username string `json:"username"`
		} `json:"results"`
	}{}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return -1, errors.New("unable to fetch user id: error reading response body")
	}

	err = json.Unmarshal(body, &data)
	if err != nil {
		return -1, errors.New("unable to fetch user id: error decoding response body")
	}

	if data.Count == 0 {
		return -1, errors.New("unable to fetch user id: user not found")
	}

	if data.Count > 1 {
		return -1, errors.New("unable to fetch user id: too many results returned")
	}

	if len(data.Results) != 1 {
		return -1, errors.New("unable to fetch user id: unexpected number of results returned")
	}

	if !strings.EqualFold(data.Results[0].Username, username) {
		return -1, errors.New("unable to fetch user id: query returned wrong user")
	}

	return data.Results[0].ID, nil
}
