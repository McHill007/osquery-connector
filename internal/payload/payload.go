package payload

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/McHill007/osquery-connector/internal/config"
)

type Envelope struct {
	Hostname      string            `json:"hostname,omitempty"`
	IP            string            `json:"ip,omitempty"`
	FQDN          string            `json:"fqdn,omitempty"`
	ScanTime      string            `json:"scanTime,omitempty"`
	ExtraFields   map[string]string `json:"extraFields,omitempty"`
	InventoryData json.RawMessage   `json:"inventoryData"`
}

type Builder struct {
	cfg      config.PayloadConfig
	hostname string
	ip       string
	fqdn     string
}

func NewBuilder(cfg config.PayloadConfig) (*Builder, error) {
	b := &Builder{cfg: cfg}

	hostname, err := os.Hostname()
	if err != nil {
		return nil, fmt.Errorf("resolving hostname: %w", err)
	}
	b.hostname = hostname
	b.ip, b.fqdn = resolveNetwork(hostname)

	return b, nil
}

func (b *Builder) ExtraFields() map[string]string { return b.cfg.ExtraFields }
func (b *Builder) Hostname() string               { return b.hostname }
func (b *Builder) FQDN() string                   { return b.fqdn }

func (b *Builder) Build(raw string) ([]byte, error) {
	rawJSON := json.RawMessage(raw)

	if !b.cfg.IncludeHeader {
		if len(b.cfg.ExtraFields) == 0 {
			return []byte(raw), nil
		}
		return mergeExtraFields(rawJSON, b.cfg.ExtraFields)
	}

	env := Envelope{
		Hostname:      b.hostname,
		IP:            b.ip,
		FQDN:          b.fqdn,
		ScanTime:      time.Now().UTC().Format(time.RFC3339),
		InventoryData: rawJSON,
	}
	if len(b.cfg.ExtraFields) > 0 {
		env.ExtraFields = b.cfg.ExtraFields
	}

	return json.Marshal(env)
}

func resolveNetwork(hostname string) (ip, fqdn string) {
	addrs, err := net.LookupHost(hostname)
	if err != nil || len(addrs) == 0 {
		addrs, err = interfaceIPs()
		if err != nil || len(addrs) == 0 {
			return "", hostname
		}
	}
	ip = addrs[0]

	names, err := net.LookupAddr(ip)
	if err != nil || len(names) == 0 {
		return ip, hostname
	}
	fqdn = names[0]
	if len(fqdn) > 0 && fqdn[len(fqdn)-1] == '.' {
		fqdn = fqdn[:len(fqdn)-1]
	}
	return ip, fqdn
}

func interfaceIPs() ([]string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var ips []string
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip != nil && ip.To4() != nil {
				ips = append(ips, ip.String())
			}
		}
	}
	return ips, nil
}

func mergeExtraFields(raw json.RawMessage, extra map[string]string) ([]byte, error) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("merging extra fields: %w", err)
	}
	extraJSON, _ := json.Marshal(extra)
	m["extraFields"] = extraJSON
	return json.Marshal(m)
}
