package easytier

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/url"
	"os"
	"strings"
	"time"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json"

	corehost "github.com/easytier/easytier/easytier-go"
	"github.com/gofrs/uuid/v5"
)

const webInstanceScanInterval = time.Second

func newWebClientOptions(options option.EasyTierEndpointOptions, tag string) (*corehost.WebClientOptions, error) {
	webOptions := options.Web
	if webOptions == nil {
		return nil, nil
	}
	if webOptions.Server == "" {
		return nil, E.New("missing web.server")
	}
	serverURL, err := url.Parse(webOptions.Server)
	if err != nil {
		return nil, E.Cause(err, "parse web.server")
	}
	if serverURL.Scheme != "tcp" && serverURL.Scheme != "udp" || serverURL.Host == "" {
		return nil, E.New("web.server must be a tcp:// or udp:// URL")
	}
	if strings.Trim(serverURL.Path, "/") == "" {
		return nil, E.New("web.server must include the user name as path")
	}
	machineID := webOptions.MachineID
	if machineID == "" {
		machineID = defaultMachineID(tag)
	} else {
		parsed, err := uuid.FromString(machineID)
		if err != nil {
			return nil, E.Cause(err, "parse web.machine_id")
		}
		machineID = parsed.String()
	}
	hostname := webOptions.Hostname
	if hostname == "" {
		hostname = options.Hostname
	}
	return &corehost.WebClientOptions{
		Endpoint:   webOptions.Server,
		MachineID:  machineID,
		Hostname:   hostname,
		SecureMode: webOptions.SecureMode,
	}, nil
}

// defaultMachineID derives a stable machine UUID from the operating system's
// machine identifier, or the hostname where none is available, and the
// endpoint tag, so that the configuration server recognizes the endpoint
// across restarts.
func defaultMachineID(tag string) string {
	seed := ""
	for _, path := range []string{"/etc/machine-id", "/var/lib/dbus/machine-id"} {
		content, err := os.ReadFile(path)
		if err == nil {
			seed = strings.TrimSpace(string(content))
			if seed != "" {
				break
			}
		}
	}
	if seed == "" {
		seed, _ = os.Hostname()
	}
	sum := sha256.Sum256([]byte("sing-box/easytier/" + seed + "/" + tag))
	sum[6] = sum[6]&0x0f | 0x50
	sum[8] = sum[8]&0x3f | 0x80
	encoded := hex.EncodeToString(sum[:16])
	return encoded[0:8] + "-" + encoded[8:12] + "-" + encoded[12:16] + "-" + encoded[16:20] + "-" + encoded[20:32]
}

// runWebClient keeps the instances created by the configuration server
// attached to the endpoint until the endpoint closes.
func (e *Endpoint) runWebClient(host *corehost.Host, local *corehost.Instance) {
	client, err := host.ConnectWebClient(e.ctx, *e.webOptions)
	if err != nil {
		e.logger.Error(E.Cause(err, "connect EasyTier Web"))
		return
	}
	defer closeWithTimeout(client.Close)
	e.logger.Info("connecting to EasyTier Web ", e.webOptions.Endpoint, " as machine ", e.webOptions.MachineID)
	attached := make(map[*corehost.Instance]*attachedInstance)
	defer func() {
		for _, instance := range attached {
			instance.close()
		}
	}()
	connected := false
	ticker := time.NewTicker(webInstanceScanInterval)
	defer ticker.Stop()
	for {
		if client.Connected() != connected {
			connected = !connected
			if connected {
				e.logger.Info("connected to EasyTier Web")
			} else {
				e.logger.Warn("disconnected from EasyTier Web, reconnecting")
			}
		}
		e.syncWebInstances(host, local, attached)
		select {
		case <-e.ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (e *Endpoint) syncWebInstances(host *corehost.Host, local *corehost.Instance, attached map[*corehost.Instance]*attachedInstance) {
	current := make(map[*corehost.Instance]bool)
	for _, instance := range host.Instances() {
		if instance == local {
			continue
		}
		current[instance] = true
		if _, loaded := attached[instance]; loaded || instance.State() != corehost.StateRunning {
			continue
		}
		attached[instance] = e.attachInstance(instance, e.webInstanceName(instance), true, addressConfig{}, nil)
	}
	for instance, attachedInstance := range attached {
		select {
		case <-attachedInstance.done:
			delete(attached, instance)
			continue
		default:
		}
		if !current[instance] {
			attachedInstance.close()
			delete(attached, instance)
			e.logger.Info("detached EasyTier Web instance ", attachedInstance.name)
		}
	}
}

func (e *Endpoint) webInstanceName(instance *corehost.Instance) string {
	ctx, cancel := context.WithTimeout(e.ctx, C.DNSTimeout)
	defer cancel()
	nodeInfo, err := instance.ShowNodeInfo(ctx)
	if err == nil {
		if networkName := tomlString(nodeInfo.GetConfig(), "network_identity", "network_name"); networkName != "" {
			return networkName
		}
	}
	return instance.ID()
}

// tomlString reads a string key from the TOML document the core reports as
// its effective configuration. section is the table name, or empty for a
// top-level key.
func tomlString(document string, section string, key string) string {
	currentSection := ""
	for _, line := range strings.Split(document, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "[") {
			currentSection = strings.Trim(line, "[] ")
			continue
		}
		if currentSection != section {
			continue
		}
		name, value, found := strings.Cut(line, "=")
		if !found || strings.TrimSpace(name) != key {
			continue
		}
		value = strings.TrimSpace(value)
		var decoded string
		if strings.HasPrefix(value, `"`) && json.Unmarshal([]byte(value), &decoded) == nil {
			return decoded
		}
		return strings.Trim(value, `'`)
	}
	return ""
}
