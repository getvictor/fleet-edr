package webhook

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"syscall"
	"time"
)

// Client POSTs signed webhook payloads to destinations. Its transport is hardened against SSRF: it dials only through DialControl
// (which rejects blocked addresses after DNS resolution), never uses an environment proxy (which could bypass that check), and does
// not follow redirects (a 3xx to an internal target is returned as-is and treated as a non-2xx by the worker). Each request is bound
// by the client timeout, and the response body is drained under a byte cap so a slow or oversized receiver cannot exhaust the worker.
type Client struct {
	http             *http.Client
	maxResponseBytes int64
}

const (
	idleConnTimeout = 90 * time.Second
	maxIdleConns    = 32
)

// NewClient builds a delivery client. timeout bounds the whole request; maxResponseBytes caps how much of the response body is read.
// It always dials through the SSRF DialControl guard.
func NewClient(timeout time.Duration, maxResponseBytes int64) *Client {
	return newClient(timeout, maxResponseBytes, DialControl)
}

// newClient builds a client with an injectable dial-control hook. Production uses DialControl; tests pass a permissive control so
// they can reach an httptest server on loopback (which DialControl rightly blocks in production).
func newClient(timeout time.Duration, maxResponseBytes int64, control func(network, address string, c syscall.RawConn) error) *Client {
	dialer := &net.Dialer{Timeout: timeout, Control: control}
	return &Client{
		http: &http.Client{
			Timeout: timeout,
			// Proxy nil: an environment proxy would dial on our behalf and bypass DialControl's resolved-IP check.
			Transport: &http.Transport{
				Proxy:                 nil,
				DialContext:           dialer.DialContext,
				ForceAttemptHTTP2:     true,
				MaxIdleConns:          maxIdleConns,
				IdleConnTimeout:       idleConnTimeout,
				TLSHandshakeTimeout:   timeout,
				ExpectContinueTimeout: time.Second,
			},
			// Do not follow redirects: return the 3xx as the final response so a redirect to an internal host is never dialed.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		maxResponseBytes: maxResponseBytes,
	}
}

// Deliver signs and POSTs body to url with the Standard Webhooks headers, returning the HTTP status code (0 on a transport error).
// The signature is computed over id.timestamp.body with the destination secret at send time, so each attempt carries a fresh
// timestamp receivers can use for replay rejection.
func (c *Client) Deliver(ctx context.Context, url, id string, timestamp int64, body, secret []byte) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return 0, fmt.Errorf("build webhook request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "fleet-edr-webhook/1")
	req.Header.Set(HeaderID, id)
	req.Header.Set(HeaderTimestamp, strconv.FormatInt(timestamp, 10))
	req.Header.Set(HeaderSignature, Sign(id, timestamp, body, secret))

	resp, err := c.http.Do(req)
	if err != nil {
		return 0, fmt.Errorf("post webhook: %w", err)
	}
	defer resp.Body.Close()
	// Drain a bounded prefix so the connection can be reused; the body itself is not needed.
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, c.maxResponseBytes))
	return resp.StatusCode, nil
}
