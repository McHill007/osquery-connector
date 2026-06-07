package main

import (
	"flag"
	"log"
	"os"
	"time"

	"github.com/McHill007/osquery-connector/internal/config"
	httpconnector "github.com/McHill007/osquery-connector/internal/connector/http"
	mqttconnector "github.com/McHill007/osquery-connector/internal/connector/mqtt"
	"github.com/McHill007/osquery-connector/internal/payload"
	osquery "github.com/osquery/osquery-go"
	"github.com/osquery/osquery-go/plugin/logger"
)

func main() {
	var (
		socket     = flag.String("socket", "", "osquery extension socket path (required)")
		timeout    = flag.Int("timeout", 3, "seconds before timeout")
		interval   = flag.Int("interval", 3, "seconds between health checks")
		configFile = flag.String("connector_config", "", "path to connector config file")
		verbose    = flag.Bool("verbose", false, "enable verbose logging")
	)
	flag.Parse()

	if *socket == "" {
		log.Fatal("--socket is required")
	}

	_ = verbose
	_ = interval

	cfg, err := config.Load(*configFile)
	if err != nil {
		log.Fatalf("loading config: %v", err)
	}

	if err := validateTopicTemplate(cfg); err != nil {
		log.Fatalf("invalid topic template: %v", err)
	}

	builder, err := payload.NewBuilder(cfg.Payload)
	if err != nil {
		log.Fatalf("initializing payload builder: %v", err)
	}

	plugins, cleanup, err := buildPlugins(cfg, builder)
	if err != nil {
		log.Fatalf("initializing connectors: %v", err)
	}
	defer cleanup()

	server, err := osquery.NewExtensionManagerServer(
		"osquery_connector",
		*socket,
		osquery.ServerTimeout(time.Duration(*timeout)*time.Second),
	)
	if err != nil {
		log.Fatalf("creating extension server: %v", err)
	}

	for _, p := range plugins {
		server.RegisterPlugin(p)
	}

	if err := server.Run(); err != nil {
		log.Fatalf("extension server error: %v", err)
	}
}

func buildPlugins(cfg *config.Config, builder *payload.Builder) ([]osquery.OsqueryPlugin, func(), error) {
	var plugins []osquery.OsqueryPlugin
	cleanup := func() {}

	switch cfg.Mode {
	case "http":
		conn := httpconnector.New(cfg.HTTP, builder)
		plugins = append(plugins, logger.NewPlugin("http_connector", conn.Log))
	case "mqtt":
		conn, err := mqttconnector.New(cfg.MQTT, builder, builder.Hostname(), builder.FQDN())
		if err != nil {
			return nil, cleanup, err
		}
		cleanup = conn.Disconnect
		plugins = append(plugins, logger.NewPlugin("mqtt_connector", conn.Log))
	case "both":
		httpConn := httpconnector.New(cfg.HTTP, builder)
		plugins = append(plugins, logger.NewPlugin("http_connector", httpConn.Log))

		mqttConn, err := mqttconnector.New(cfg.MQTT, builder, builder.Hostname(), builder.FQDN())
		if err != nil {
			return nil, cleanup, err
		}
		cleanup = mqttConn.Disconnect
		plugins = append(plugins, logger.NewPlugin("mqtt_connector", mqttConn.Log))
	default:
		log.Printf("unknown mode %q, defaulting to http", cfg.Mode)
		conn := httpconnector.New(cfg.HTTP, builder)
		plugins = append(plugins, logger.NewPlugin("http_connector", conn.Log))
	}

	return plugins, cleanup, nil
}

func validateTopicTemplate(cfg *config.Config) error {
	if cfg.Mode != "mqtt" && cfg.Mode != "both" {
		return nil
	}
	return nil // full validation happens in mqtt connector at runtime
}

func init() {
	log.SetOutput(os.Stderr)
	log.SetFlags(log.LstdFlags | log.Lshortfile)
}
