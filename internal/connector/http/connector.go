package httpconnector

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/McHill007/osquery-connector/internal/config"
	"github.com/McHill007/osquery-connector/internal/payload"
	"github.com/osquery/osquery-go/plugin/logger"
)

type Connector struct {
	cfg     config.HTTPConfig
	builder *payload.Builder
	client  *http.Client
}

func New(cfg config.HTTPConfig, builder *payload.Builder) *Connector {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: !cfg.TLSVerify}, //nolint:gosec
	}
	return &Connector{
		cfg:     cfg,
		builder: builder,
		client: &http.Client{
			Timeout:   time.Duration(cfg.TimeoutSeconds) * time.Second,
			Transport: transport,
		},
	}
}

func (c *Connector) Log(_ context.Context, typ logger.LogType, logText string) error {
	if typ == logger.LogTypeSnapshot || typ == logger.LogTypeString {
		return c.send(logText)
	}
	return nil
}

func (c *Connector) send(raw string) error {
	body, err := c.builder.Build(raw)
	if err != nil {
		return fmt.Errorf("building payload: %w", err)
	}

	var lastErr error
	for attempt := 1; attempt <= c.cfg.Retry.MaxAttempts; attempt++ {
		if err := c.doRequest(body); err != nil {
			lastErr = err
			log.Printf("[http-connector] attempt %d/%d failed: %v", attempt, c.cfg.Retry.MaxAttempts, err)
			time.Sleep(time.Duration(c.cfg.Retry.BackoffSeconds) * time.Second)
			continue
		}
		return nil
	}
	return fmt.Errorf("all %d attempts failed: %w", c.cfg.Retry.MaxAttempts, lastErr)
}

func (c *Connector) doRequest(body []byte) error {
	req, err := http.NewRequest(c.cfg.Method, c.cfg.Endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")
	for k, v := range c.cfg.Headers {
		req.Header.Set(k, v)
	}
	c.applyAuth(req)

	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("server returned %d", resp.StatusCode)
	}
	return nil
}

func (c *Connector) applyAuth(req *http.Request) {
	switch c.cfg.Auth.Type {
	case "bearer":
		req.Header.Set("Authorization", "Bearer "+c.cfg.Auth.Token)
	case "basic":
		req.SetBasicAuth(c.cfg.Auth.Username, c.cfg.Auth.Password)
	case "apikey":
		req.Header.Set(c.cfg.Auth.Header, c.cfg.Auth.Token)
	}
}
