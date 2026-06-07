package mqttconnector

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	mqtt "github.com/eclipse/paho.mqtt.golang"
	"github.com/McHill007/osquery-connector/internal/config"
	"github.com/McHill007/osquery-connector/internal/payload"
	osquerylogger "github.com/osquery/osquery-go/plugin/logger"
)

type Connector struct {
	cfg      config.MQTTConfig
	builder  *payload.Builder
	client   mqtt.Client
	hostname string
	fqdn     string
}

func New(cfg config.MQTTConfig, builder *payload.Builder, hostname, fqdn string) (*Connector, error) {
	opts := mqtt.NewClientOptions().
		AddBroker(cfg.Broker).
		SetClientID(cfg.ClientID).
		SetAutoReconnect(true)

	if err := applyAuth(opts, cfg); err != nil {
		return nil, err
	}

	client := mqtt.NewClient(opts)
	if token := client.Connect(); token.Wait() && token.Error() != nil {
		return nil, fmt.Errorf("connecting to broker: %w", token.Error())
	}

	return &Connector{
		cfg:      cfg,
		builder:  builder,
		client:   client,
		hostname: hostname,
		fqdn:     fqdn,
	}, nil
}

func (c *Connector) Log(_ context.Context, typ osquerylogger.LogType, logText string) error {
	if typ == osquerylogger.LogTypeSnapshot || typ == osquerylogger.LogTypeString {
		return c.publish(logText)
	}
	return nil
}

func (c *Connector) publish(raw string) error {
	body, err := c.builder.Build(raw)
	if err != nil {
		return fmt.Errorf("building payload: %w", err)
	}

	queryName := extractQueryName(raw)
	topic := c.resolveTopic(queryName)

	var lastErr error
	for attempt := 1; attempt <= c.cfg.Retry.MaxAttempts; attempt++ {
		token := c.client.Publish(topic, byte(c.cfg.QoS), c.cfg.Retain, body)
		token.Wait()
		if token.Error() == nil {
			return nil
		}
		lastErr = token.Error()
		log.Printf("[mqtt-connector] attempt %d/%d failed: %v", attempt, c.cfg.Retry.MaxAttempts, lastErr)
		time.Sleep(time.Duration(c.cfg.Retry.BackoffSeconds) * time.Second)
	}
	return fmt.Errorf("all %d attempts failed: %w", c.cfg.Retry.MaxAttempts, lastErr)
}

func (c *Connector) resolveTopic(queryName string) string {
	topic := c.cfg.TopicTemplate
	topic = strings.ReplaceAll(topic, "{hostname}", c.hostname)
	topic = strings.ReplaceAll(topic, "{fqdn}", c.fqdn)
	topic = strings.ReplaceAll(topic, "{query_name}", queryName)

	for k, v := range c.builder.ExtraFields() {
		topic = strings.ReplaceAll(topic, "{"+k+"}", v)
	}
	return topic
}

func extractQueryName(raw string) string {
	// fast path: find "name":"..." without full JSON parse
	const key = `"name":"`
	idx := strings.Index(raw, key)
	if idx == -1 {
		return "unknown"
	}
	start := idx + len(key)
	end := strings.Index(raw[start:], `"`)
	if end == -1 {
		return "unknown"
	}
	return raw[start : start+end]
}

func (c *Connector) Disconnect() {
	if c.client != nil && c.client.IsConnected() {
		c.client.Disconnect(250)
	}
}

func applyAuth(opts *mqtt.ClientOptions, cfg config.MQTTConfig) error {
	switch cfg.Auth.Type {
	case "password":
		opts.SetUsername(cfg.Auth.Username)
		opts.SetPassword(cfg.Auth.Password)
	case "certificate":
		tlsCfg, err := newTLSConfig(cfg.TLS)
		if err != nil {
			return err
		}
		opts.SetTLSConfig(tlsCfg)
	}

	if cfg.TLS.Enabled && cfg.Auth.Type != "certificate" {
		tlsCfg, err := newTLSConfig(cfg.TLS)
		if err != nil {
			return err
		}
		opts.SetTLSConfig(tlsCfg)
	}
	return nil
}

func newTLSConfig(cfg config.MQTTTLS) (*tls.Config, error) {
	tlsCfg := &tls.Config{}

	if cfg.CAFile != "" {
		caCert, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("reading CA file: %w", err)
		}
		pool := x509.NewCertPool()
		pool.AppendCertsFromPEM(caCert)
		tlsCfg.RootCAs = pool
	}

	if cfg.CertFile != "" && cfg.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("loading client certificate: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}

	return tlsCfg, nil
}
