package main

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type LocalStatus struct {
	Version string                `json:"Version"`
	Self    *LocalNode            `json:"Self"`
	Peers   map[string]*LocalNode `json:"Peer"`
	Users   map[string]*LocalUser `json:"User"`
}

type LocalNode struct {
	ID           string    `json:"ID"`
	HostName     string    `json:"HostName"`
	DNSName      string    `json:"DNSName"`
	OS           string    `json:"OS"`
	Online       bool      `json:"Online"`
	UserID       uint64    `json:"UserID"`
	Created      time.Time `json:"Created"`
	LastSeen     time.Time `json:"LastSeen"`
	KeyExpiryRaw string    `json:"KeyExpiry"` // parse separately; sometimes absent or empty
	KeyExpiry    time.Time `json:"-"`
}

type LocalUser struct {
	ID          uint64 `json:"ID"`
	LoginName   string `json:"LoginName"`
	DisplayName string `json:"DisplayName"`
}

// fetchLocalStatus queries the tailscaled LocalAPI over a unix domain socket.
func fetchLocalStatus(socketPath string) (*LocalStatus, error) {
	if socketPath == "" {
		return nil, errors.New("empty socket path")
	}
	dialer := func(ctx context.Context, network, addr string) (net.Conn, error) {
		// Ignore supplied network/addr; always use unix socket.
		return (&net.Dialer{}).DialContext(ctx, "unix", socketPath)
	}
	tr := &http.Transport{DialContext: dialer}
	client := &http.Client{Transport: tr, Timeout: 5 * time.Second}

	req, err := http.NewRequest("GET", "http://local-tailscaled.sock/localapi/v0/status", nil)
	if err != nil {
		return nil, err
	}
	// Host header must be set (some handlers may rely on it).
	req.Host = "local-tailscaled.sock"
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, errors.New(resp.Status)
	}
	var st LocalStatus
	dec := json.NewDecoder(resp.Body)
	if err := dec.Decode(&st); err != nil {
		return nil, err
	}
	// Parse key expiry for Self & Peers
	parseKE := func(n *LocalNode) {
		if n == nil || n.KeyExpiryRaw == "" {
			return
		}
		if t, err := time.Parse(time.RFC3339, n.KeyExpiryRaw); err == nil {
			n.KeyExpiry = t
		}
	}
	parseKE(st.Self)
	for _, p := range st.Peers {
		parseKE(p)
	}
	return &st, nil
}

// updateLocalAPIMetrics converts LocalStatus into the same metrics used for central API mode.
func (a *AppConfig) updateLocalAPIMetrics(ls *LocalStatus) {
	if ls == nil {
		return
	}
	// Helper to map user ID to a string label.
	userLabel := func(id uint64) string {
		key := uintToString(id)
		if u, ok := ls.Users[key]; ok {
			if u.LoginName != "" {
				return u.LoginName
			}
			if u.DisplayName != "" {
				return u.DisplayName
			}
		}
		return key
	}

	// Single writer for metrics (same goroutine) so no locking needed.
	upsert := func(n *LocalNode) {
		if n == nil {
			return
		}
		hostname := strings.Split(n.DNSName, ".")[0]
		// UpdateAvailable
		a.APIMetrics["tailscale_hosts"].WithLabelValues(
			hostname,
			"false", // update_available
			n.OS,
			"false", // TODO: is external
			userLabel(n.UserID),
			ls.Version,
			"", // tags not available
		).Set(1)
		setTime := func(metric string, t time.Time) {
			v := float64(0)
			if !t.IsZero() {
				v = float64(t.Unix())
			}
			a.APIMetrics[metric].WithLabelValues(hostname).Set(v)
		}
		setTime("tailscale_host_created_timestamp", n.Created)
		setTime("tailscale_host_expires_timestamp", n.KeyExpiry)
		if n.LastSeen.IsZero() && n.Online {
			a.APIMetrics["tailscale_host_last_seen_timestamp"].WithLabelValues(hostname).Set(float64(time.Now().Unix()))
		} else {
			setTime("tailscale_host_last_seen_timestamp", n.LastSeen)
		}
	}
	upsert(ls.Self)
	for _, p := range ls.Peers {
		upsert(p)
	}
}

// uintToString converts a uint64 to string without importing strconv multiple times here.
func uintToString(v uint64) string { return strconv.FormatUint(v, 10) }
