package config

import (
	"errors"
	"fmt"

	"github.com/spf13/viper"
)

type Config struct {
	Mode    string        `mapstructure:"mode"`
	HTTP    HTTPConfig    `mapstructure:"http"`
	MQTT    MQTTConfig    `mapstructure:"mqtt"`
	Payload PayloadConfig `mapstructure:"payload"`
}

type HTTPConfig struct {
	Endpoint       string            `mapstructure:"endpoint"`
	Method         string            `mapstructure:"method"`
	TimeoutSeconds int               `mapstructure:"timeout_seconds"`
	TLSVerify      bool              `mapstructure:"tls_verify"`
	Auth           HTTPAuth          `mapstructure:"auth"`
	Headers        map[string]string `mapstructure:"headers"`
	Retry          RetryConfig       `mapstructure:"retry"`
}

type HTTPAuth struct {
	Type     string `mapstructure:"type"`
	Token    string `mapstructure:"token"`
	Username string `mapstructure:"username"`
	Password string `mapstructure:"password"`
	Header   string `mapstructure:"header"`
}

type MQTTConfig struct {
	Broker        string      `mapstructure:"broker"`
	TopicTemplate string      `mapstructure:"topic_template"`
	QoS           int         `mapstructure:"qos"`
	Retain        bool        `mapstructure:"retain"`
	ClientID      string      `mapstructure:"client_id"`
	Auth          MQTTAuth    `mapstructure:"auth"`
	TLS           MQTTTLS     `mapstructure:"tls"`
	Retry         RetryConfig `mapstructure:"retry"`
}

type MQTTAuth struct {
	Type     string `mapstructure:"type"`
	Username string `mapstructure:"username"`
	Password string `mapstructure:"password"`
}

type MQTTTLS struct {
	Enabled  bool   `mapstructure:"enabled"`
	CAFile   string `mapstructure:"ca_file"`
	CertFile string `mapstructure:"cert_file"`
	KeyFile  string `mapstructure:"key_file"`
}

type RetryConfig struct {
	MaxAttempts    int `mapstructure:"max_attempts"`
	BackoffSeconds int `mapstructure:"backoff_seconds"`
}

type PayloadConfig struct {
	IncludeHeader bool              `mapstructure:"include_header"`
	ExtraFields   map[string]string `mapstructure:"extra_fields"`
}

func Load(configFile string) (*Config, error) {
	v := viper.New()

	setDefaults(v)

	if configFile != "" {
		v.SetConfigFile(configFile)
		if err := v.ReadInConfig(); err != nil {
			var notFound *viper.ConfigFileNotFoundError
			if !errors.As(err, &notFound) {
				return nil, fmt.Errorf("reading config file: %w", err)
			}
		}
	}

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}

	return &cfg, nil
}

func setDefaults(v *viper.Viper) {
	v.SetDefault("mode", "http")

	v.SetDefault("http.method", "POST")
	v.SetDefault("http.timeout_seconds", 10)
	v.SetDefault("http.tls_verify", true)
	v.SetDefault("http.auth.type", "none")
	v.SetDefault("http.retry.max_attempts", 3)
	v.SetDefault("http.retry.backoff_seconds", 2)

	v.SetDefault("mqtt.qos", 1)
	v.SetDefault("mqtt.retain", false)
	v.SetDefault("mqtt.client_id", "osquery-connector")
	v.SetDefault("mqtt.auth.type", "none")
	v.SetDefault("mqtt.tls.enabled", false)
	v.SetDefault("mqtt.retry.max_attempts", 3)
	v.SetDefault("mqtt.retry.backoff_seconds", 2)

	v.SetDefault("payload.include_header", true)
}
