# osquery-connector — Design Document

## Overview

`osquery-connector` is a standalone osquery extension that forwards osquery scheduled query results to external systems via HTTP or MQTT (or both). It is implemented as a single Go binary (`osquery-connector.ext`) that registers as a **Logger Plugin** in the osquery extension framework.

The connector runs as a separate process alongside `osqueryd`, communicates via the osquery Thrift API (named pipes on Windows, Unix domain sockets on Linux/macOS), and is activated through osquery's standard extension autoload mechanism.

---

## Architecture

```
osqueryd
  │
  │  Thrift IPC (named pipe / unix socket)
  │
  └─► osquery-connector.ext
          │
          ├─► HTTP Connector  ──► REST endpoint (JSON POST)
          └─► MQTT Connector  ──► MQTT broker (publish)
```

- Single binary, both connectors compiled in
- Active connector(s) selected via configuration
- Implements the osquery `LoggerPlugin` interface via `osquery-go`

---

## Project Structure

```
osquery-connector/
├── cmd/
│   └── connector/
│       └── main.go              # Entry point, flag parsing, extension bootstrap
├── internal/
│   ├── config/
│   │   └── config.go            # Config file loading and validation
│   ├── payload/
│   │   └── payload.go           # Payload envelope (with/without header)
│   ├── http/
│   │   └── connector.go         # HTTP logger plugin implementation
│   └── mqtt/
│       └── connector.go         # MQTT logger plugin implementation
├── go.mod
├── go.sum
├── DESIGN.md
└── .gitignore
```

---

## Dependencies

| Package | Purpose |
|---|---|
| `github.com/osquery/osquery-go` | osquery Thrift extension SDK |
| `github.com/eclipse/paho.mqtt.golang` | MQTT client |

---

## Configuration

Configuration is layered with the following precedence (highest to lowest):

1. **CLI flags / osquery flags** — override everything, useful for testing and one-off overrides
2. **JSON config file** — primary configuration for structured settings
3. **Defaults** — built-in fallback values

The config file is **optional**. Simple deployments without secrets can use flags only via `--flagfile`. The config file is recommended when:
- Secrets (tokens, passwords) must not appear in the process list
- `extra_fields` contains multiple arbitrary key-value pairs

### osquery Flags

Passed via `--flagfile` or directly on the command line:

```sh
--connector_config=/etc/osquery/connector.json
--connector_mode=http             # http | mqtt | both
--allow_unsafe                    # development only: skip permission checks
```

### Config File Schema (`connector.json`)

```json
{
  "mode": "both",

  "http": {
    "endpoint": "https://my-server/ingest",
    "method": "POST",
    "timeout_seconds": 10,
    "tls_verify": true,
    "auth": {
      "type": "bearer",
      "token": "secret-token"
    },
    "headers": {
      "X-Source": "osquery"
    },
    "retry": {
      "max_attempts": 3,
      "backoff_seconds": 2
    }
  },

  "mqtt": {
    "broker": "mqtt://localhost:1883",
    "topic_template": "osquery/{hostname}/{query_name}",
    "qos": 1,
    "retain": false,
    "client_id": "osquery-connector",
    "auth": {
      "type": "password",
      "username": "user",
      "password": "secret"
    },
    "tls": {
      "enabled": false,
      "ca_file": "/etc/certs/ca.pem",
      "cert_file": "/etc/certs/client.pem",
      "key_file": "/etc/certs/client.key"
    },
    "retry": {
      "max_attempts": 3,
      "backoff_seconds": 2
    }
  },

  "payload": {
    "include_header": true,
    "extra_fields": {
      "environment": "production",
      "site": "berlin",
      "customer": "acme-corp",
      "framework": "CIS",
      "snow_id": "CI1234567",
      "cost_center": "IT-42"
    }
  }
}
```

### HTTP Auth Types

| Type | Fields |
|---|---|
| `none` | — |
| `bearer` | `token` |
| `basic` | `username`, `password` |
| `apikey` | `header` (header name), `token` |

### MQTT Auth Types

| Type | Fields |
|---|---|
| `none` | — |
| `password` | `username`, `password` |
| `certificate` | Uses `tls.cert_file`, `tls.key_file`, `tls.ca_file` |

---

## Extra Fields

`extraFields` is a set of key-value pairs that are attached to every payload sent by the connector. They can be defined in the config file or passed dynamically at startup via CLI flags — for example, injected by an orchestration framework or deployment pipeline. The values are fixed for the lifetime of the connector process and require no changes to the osquery schedule or queries.

### Behavior

- `extraFields` is **always sent** as a nested object in every payload
- It is included in **both** `include_header: true` and `include_header: false` mode
- If no `extra_fields` are configured, the `extraFields` object is omitted from the payload
- Values can be strings or numbers

### Use Cases

| Key | Example Value | Purpose |
|---|---|---|
| `customer` | `"acme-corp"` | Identify the customer in a multi-tenant setup |
| `framework` | `"CIS"` | Compliance framework the query relates to |
| `snow_id` | `"CI1234567"` | ServiceNow Configuration Item ID |
| `cost_center` | `"IT-42"` | Internal cost center for billing/chargeback |
| `environment` | `"production"` | Deployment environment |
| `site` | `"berlin"` | Physical or logical site |

### Config

```json
"payload": {
  "include_header": true,
  "extra_fields": {
    "customer": "acme-corp",
    "framework": "CIS",
    "snow_id": "CI1234567",
    "cost_center": "IT-42",
    "environment": "production",
    "site": "berlin"
  }
}
```

---

## Payload Format

### With Header (`include_header: true`)

```json
{
  "hostname": "my-host",
  "ip": "192.168.1.100",
  "fqdn": "my-host.domain.com",
  "scanTime": "2026-06-07T10:00:00Z",
  "extraFields": {
    "environment": "production",
    "site": "berlin",
    "customer": "acme-corp",
    "framework": "CIS",
    "snow_id": "CI1234567",
    "cost_center": "IT-42"
  },
  "inventoryData": {
    "action": "added",
    "columns": { "pid": "1234", "name": "osqueryd" },
    "name": "running_processes",
    "hostIdentifier": "my-host",
    "calendarTime": "Sat Jun  7 10:00:00 2026 UTC",
    "unixTime": "1749290400",
    "epoch": "1",
    "counter": "1"
  }
}
```

**Auto-populated header fields** (resolved at runtime):

| Field | Source |
|---|---|
| `hostname` | `os.Hostname()` |
| `ip` | first non-loopback IPv4 address |
| `fqdn` | DNS reverse lookup of IP |
| `scanTime` | UTC timestamp of log event |

**Extra fields** from `payload.extra_fields` are always included as a nested `extraFields` object — regardless of `include_header`.

### Without Header (`include_header: false`)

No auto-populated system fields (`hostname`, `ip`, `fqdn`, `scanTime`). Extra fields and raw osquery data are merged at the top level:

```json
{
  "extraFields": {
    "environment": "production",
    "site": "berlin",
    "customer": "acme-corp",
    "framework": "CIS",
    "snow_id": "CI1234567",
    "cost_center": "IT-42"
  },
  "action": "added",
  "columns": { "pid": "1234", "name": "osqueryd" },
  "name": "running_processes",
  "hostIdentifier": "my-host",
  "calendarTime": "Sat Jun  7 10:00:00 2026 UTC",
  "unixTime": "1749290400",
  "epoch": "1",
  "counter": "1"
}
```

---

## MQTT Topic Template

In MQTT, a topic is the address of a message — subscribers filter messages by subscribing to specific topics or wildcard patterns. The topic template defines how each osquery result is routed on the broker.

The `topic_template` supports two categories of placeholders:

### Built-in Placeholders

| Placeholder | Value |
|---|---|
| `{hostname}` | machine hostname |
| `{fqdn}` | fully qualified domain name |
| `{query_name}` | osquery scheduled query name |

### Extra Fields Placeholders

Any key defined in `extra_fields` is automatically available as a placeholder. No additional mapping required.

| Placeholder | Resolved From |
|---|---|
| `{customer}` | `extra_fields.customer` |
| `{framework}` | `extra_fields.framework` |
| `{environment}` | `extra_fields.environment` |
| `{site}` | `extra_fields.site` |
| *(any extra_fields key)* | `extra_fields.<key>` |

### Examples

```
osquery/{hostname}/{query_name}
→ osquery/server-berlin-01/running_processes

osquery/{customer}/{environment}/{hostname}/{query_name}
→ osquery/acme-corp/production/server-berlin-01/running_processes
```

### Error Handling

If a placeholder is used in the template but the corresponding key is not available (not in built-ins and not in `extra_fields`), the connector will:

1. Log an error at startup and refuse to start
2. Clearly state which placeholder is unresolved and where to configure it

This prevents silent routing failures where messages land on a malformed topic like `osquery//running_processes`.

---

## Batching

Batching is handled by osquery, not by the connector.

By setting `logger_event_type=false` in the osquery flags, osquery bundles all rows of a single query execution into one JSON object before calling the logger plugin. The connector forwards this as a single payload — no internal buffering required.

```sh
# osquery.flags
--logger_event_type=false
```

With `logger_event_type=true` (default), osquery calls the logger once per changed row. The connector forwards each call immediately.

The connector itself does not implement any additional batching layer.

---

## Error Handling

On delivery failure (connection refused, timeout, server error):

1. Retry up to `retry.max_attempts` times
2. Wait `retry.backoff_seconds` between attempts (linear backoff)
3. On max retries exceeded: log error via osquery status logger and discard event
4. No persistent local buffer (out of scope)

---

## Deployment

### 1. Build the Extension

```sh
go build -o osquery-connector.ext ./cmd/connector
```

### 2. Place the Binary

Copy the binary to the osquery extensions directory:

| OS | Default Path |
|---|---|
| Windows | `C:\Program Files\osquery\extensions\osquery-connector.ext` |
| Linux | `/usr/lib/osquery/extensions/osquery-connector.ext` |

### 3. Set File Permissions

osquery refuses to load an extension if the binary is writable by non-privileged users.

**Windows:**
```powershell
icacls "C:\Program Files\osquery\extensions" /setowner Administrators /t
icacls "C:\Program Files\osquery\extensions" /grant Administrators:f /t
icacls "C:\Program Files\osquery\extensions" /inheritance:r /t
```

**Linux:**
```sh
sudo chown root:root /usr/lib/osquery/extensions/osquery-connector.ext
sudo chmod 755 /usr/lib/osquery/extensions/osquery-connector.ext
```

### 4. Register the Extension

Create or extend the autoload file:

**`extensions.load`:**
```
C:\Program Files\osquery\extensions\osquery-connector.ext
```

### 5. Configure osquery

Add the following to the osquery flags file (`osquery.flags`). This file is read by osqueryd at startup and is the standard way to configure osquery and its extensions persistently.

| OS | Default Path |
|---|---|
| Windows | `C:\Program Files\osquery\osquery.flags` |
| Linux | `/etc/osquery/osquery.flags` |

```sh
# Load extensions from this file
--extensions_autoload=C:\Program Files\osquery\extensions\extensions.load

# Register the connector as the active logger plugin
--logger_plugin=http_connector

# Point to the connector config file
--connector_config=C:\Program Files\osquery\extensions\connector.json

# Deliver full query results as one payload (recommended)
--logger_event_type=false
```

### 6. Restart osqueryd

```sh
# Windows
Restart-Service osqueryd

# Linux
sudo systemctl restart osqueryd
```
