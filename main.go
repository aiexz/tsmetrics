package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/oauth2/clientcredentials"
	tscg "tailscale.com/client/tailscale/v2"
)

type MetricType int

const (
	logApiDateFormat            = "2006-01-02T15:04:05.000000000Z"
	CounterMetric    MetricType = iota
	GaugeMetric
)

var (
	addr         = flag.String("addr", ":9100", "address to listen on")
	waitTimeSecs = flag.Int("wait-secs", 60, "waiting time after getting new data")
	resolveNames = flag.Bool("resolve-names", false, "convert tailscale IP addresses to hostnames")
	authModeFlag = flag.String("auth-mode", "", "authentication mode: oauth|apikey|local (leave empty to auto-detect from env)")
	localSocket  = flag.String("local-socket", "/var/run/tailscale/tailscaled.sock", "path to local tailscaled socket (local mode)")
)

type AppConfig struct {
	TailNetName          string
	ClientId             string
	ClientSecret         string
	APIKey               string
	LogMetrics           map[string]*prometheus.CounterVec
	APIMetrics           map[string]*prometheus.GaugeVec
	SleepIntervalSeconds int
	LMData               *LogMetricData
	NamesByAddr          map[netip.Addr]string
	AuthMode             AuthMode
	LocalSocketPath      string
}

type AuthMode int

const (
	AuthOAuth AuthMode = iota
	AuthAPIKey
	AuthLocal
)

func (m AuthMode) String() string {
	switch m {
	case AuthOAuth:
		return "oauth"
	case AuthAPIKey:
		return "apikey"
	case AuthLocal:
		return "local"
	default:
		return "unknown"
	}
}

func parseAuthMode(s string) (AuthMode, error) {
	switch strings.ToLower(s) {
	case "oauth":
		return AuthOAuth, nil
	case "apikey":
		return AuthAPIKey, nil
	case "local":
		return AuthLocal, nil
	default:
		return AuthOAuth, errors.New("invalid auth-mode; must be one of oauth|apikey|local")
	}
}

// detectAuthMode chooses an auth mode based on provided environment values.
// Priority:
//  1. LOCAL_MODE=true => local
//  2. TS_API_KEY present => apikey
//  3. OAUTH_CLIENT_ID + OAUTH_CLIENT_SECRET present => oauth
//  4. Fallback oauth (will later fail validation if creds missing)
func detectAuthMode(localModeEnv, apiKey, clientID, clientSecret string) AuthMode {
	if localModeEnv == "true" || localModeEnv == "1" || localModeEnv == "yes" { // local override
		return AuthLocal
	}
	if apiKey != "" {
		return AuthAPIKey
	}
	if clientID != "" && clientSecret != "" {
		return AuthOAuth
	}
	return AuthOAuth
}

type LogClient interface {
	Get(string) (*http.Response, error)
}

func main() {
	flag.Parse()
	// Gather env first (used for auto-detection)
	tailnetName := os.Getenv("TAILNET_NAME")
	clientId := os.Getenv("OAUTH_CLIENT_ID")
	clientSecret := os.Getenv("OAUTH_CLIENT_SECRET")
	apiKey := os.Getenv("TS_API_KEY")
	localModeEnv := strings.ToLower(os.Getenv("LOCAL_MODE"))

	var mode AuthMode
	var err error
	if *authModeFlag != "" { // explicit override
		mode, err = parseAuthMode(*authModeFlag)
		if err != nil {
			log.Fatal(err)
		}
	} else {
		mode = detectAuthMode(localModeEnv, apiKey, clientId, clientSecret)
		log.Printf("auth mode auto-detected: %s", mode.String())
		// If we fell back to oauth (no creds) but have an accessible local
		// tailscaled socket, transparently switch to local mode. This removes
		// the need to set LOCAL_MODE explicitly (and thus need for TAILNET_NAME)
		// for common local exporter use-cases.
		if mode == AuthOAuth && tailnetName == "" && apiKey == "" && clientId == "" && clientSecret == "" {
			if fi, err := os.Stat(*localSocket); err == nil && !fi.IsDir() {
				mode = AuthLocal
				log.Printf("auth mode auto-adjusted: local (no creds & local socket present)")
			}
		}
	}

	// Validate required pieces based on detected mode
	if mode != AuthLocal && tailnetName == "" {
		log.Fatal("TAILNET_NAME must be set for oauth or apikey modes")
	}
	switch mode {
	case AuthOAuth:
		if clientId == "" || clientSecret == "" {
			log.Fatal("OAUTH_CLIENT_ID and OAUTH_CLIENT_SECRET must be set (or provide TS_API_KEY / LOCAL_MODE)")
		}
	case AuthAPIKey:
		if apiKey == "" {
			log.Fatal("TS_API_KEY must be set (or provide OAUTH_CLIENT_ID / LOCAL_MODE)")
		}
	case AuthLocal:
		if *localSocket == "" {
			log.Fatal("local-socket path required for local mode")
		}
	}

	app := AppConfig{
		TailNetName:          tailnetName,
		ClientId:             clientId,
		ClientSecret:         clientSecret,
		APIKey:               apiKey,
		LogMetrics:           map[string]*prometheus.CounterVec{},
		APIMetrics:           map[string]*prometheus.GaugeVec{},
		SleepIntervalSeconds: *waitTimeSecs,
		LMData:               &LogMetricData{},
		AuthMode:             mode,
		LocalSocketPath:      *localSocket,
	}

	if *resolveNames && app.AuthMode != AuthLocal { // name resolution requires central API currently
		client := app.getCentralHTTPClient()
		if client != nil {
			app.NamesByAddr = mustMakeNamesByAddr(&tailnetName, client)
		}
	}

	app.LMData.Init()
	app.addHandlers()

	// Only register log metrics if we can talk to central API (oauth or apikey)
	if app.AuthMode != AuthLocal {
		app.registerLogMetrics()
	} else {
		log.Printf("auth-mode=local: network log metrics disabled (central API required)")
	}
	app.registerAPIMetrics()

	if app.AuthMode != AuthLocal {
		go app.produceLogDataLoop()
	}
	go app.produceAPIDataLoop()

	modeStr := mode.String()
	if *authModeFlag != "" {
		modeStr = *authModeFlag // keep user-specified string
	}
	log.Printf("starting server on %s (auth-mode=%s)", *addr, modeStr)
	if err := http.ListenAndServe(*addr, nil); err != nil {
		panic(err)
	}
}

func (a *AppConfig) produceLogDataLoop() {
	log.Printf("log loop: starting")
	for {
		client := a.getCentralHTTPClient()
		if client == nil {
			log.Printf("log loop: no central API client available; exiting loop")
			return
		}
		a.getNewLogData(client)
		a.consumeNewLogData()
		log.Printf("log loop: sleeping for %d secs", a.SleepIntervalSeconds)
		time.Sleep(time.Duration(a.SleepIntervalSeconds) * time.Second)
	}
}

// getCentralHTTPClient returns an *http.Client capable of talking to the
// central Tailscale API based on the configured auth mode. Returns nil for
// local mode (no central API access).
func (a *AppConfig) getCentralHTTPClient() *http.Client {
	switch a.AuthMode {
	case AuthOAuth:
		var oauthConfig = &clientcredentials.Config{
			ClientID:     a.ClientId,
			ClientSecret: a.ClientSecret,
			TokenURL:     "https://api.tailscale.com/api/v2/oauth/token",
		}
		return oauthConfig.Client(context.Background())
	case AuthAPIKey:
		return newAPIKeyHTTPClient(a.APIKey)
	default:
		return nil
	}
}

// apiKeyTransport injects HTTP Basic auth with the API key.
type apiKeyTransport struct {
	apiKey string
	rt     http.RoundTripper
}

func (t *apiKeyTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	// Basic auth username is the API key, password empty
	token := base64.StdEncoding.EncodeToString([]byte(t.apiKey + ":"))
	r2 := r.Clone(r.Context())
	r2.Header.Set("Authorization", "Basic "+token)
	return t.rt.RoundTrip(r2)
}

func newAPIKeyHTTPClient(apiKey string) *http.Client {
	return &http.Client{Transport: &apiKeyTransport{apiKey: apiKey, rt: http.DefaultTransport}}
}

// Iterate over the metrics data structure and update metrics as necessary
func (a *AppConfig) getNewLogData(client LogClient) {
	now := time.Now()
	start := now.Add(-time.Duration(a.SleepIntervalSeconds) * time.Minute).Format(logApiDateFormat)
	end := now.Format(logApiDateFormat)
	apiUrl := fmt.Sprintf("https://api.tailscale.com/api/v2/tailnet/%s/network-logs?start=%s&end=%s", a.TailNetName, start, end)
	resp, err := client.Get(apiUrl)
	if err != nil {
		log.Printf("error getNewLogData(): %s %v", apiUrl, err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("error getNewLogData(): Unexpected status code: %d", resp.StatusCode)
		return
	}

	// Read the response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("error getNewLogData(): Failed to read response body: %v", err)
		return
	}

	// Unmarshal the JSON data into the struct
	var apiResponse APILogResponse
	err = json.Unmarshal(body, &apiResponse)
	if err != nil {
		log.Printf("error getNewLogData(): Failed to unmarshal JSON response: %v", err)
		return
	}

	a.LMData.SaveNewData(apiResponse)
}

func (a *AppConfig) consumeNewLogData() {
	log.Printf("consuming new log metric data\n")
	// Iterate over all the counters and update them with the data
	for name, counter := range a.LogMetrics {
		a.LMData.AddCounter(name, counter, a.NamesByAddr)
	}
	// We have updated the prometheus counters, reset the counters in the
	// data structure. We do so because these are counters so we are always
	// adding to them.
	a.LMData.Init()
}

func (a *AppConfig) registerLogMetrics() {
	labels := []string{"src", "dst", "traffic_type", "proto"}
	n := "tailscale_tx_bytes"
	a.LogMetrics[n] = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: n,
		Help: "Total number of bytes transmitted",
	}, labels)

	n = "tailscale_rx_bytes"
	a.LogMetrics[n] = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: n,
		Help: "Total number of bytes received",
	}, labels)

	n = "tailscale_tx_packets"
	a.LogMetrics[n] = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: n,
		Help: "Total number of packets transmitted",
	}, labels)

	n = "tailscale_rx_packets"
	a.LogMetrics[n] = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: n,
		Help: "Total number of packets received",
	}, labels)

	for name := range a.LogMetrics {
		prometheus.MustRegister(a.LogMetrics[name])
	}
}

func (a *AppConfig) registerAPIMetrics() {
	// Static-ish host metadata. Tags are joined into a single label value.
	labels := []string{"hostname", "update_available", "os", "is_external", "user", "client_version", "tags"}
	n := "tailscale_hosts"
	a.APIMetrics[n] = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: n,
		Help: "Hosts in the tailnet (value 1 per host; tags joined by comma)",
	}, labels)
	prometheus.MustRegister(a.APIMetrics[n])

	// Dynamic timestamp metrics (unix epoch seconds) per host.
	for _, metric := range []struct{ name, help string }{
		{"tailscale_host_created_timestamp", "Host creation time (unix epoch seconds; 0 if unknown)"},
		{"tailscale_host_last_seen_timestamp", "Last seen time recorded by Tailscale (unix epoch seconds; 0 if never)"},
		{"tailscale_host_expires_timestamp", "Auth key / node key expiry time (unix epoch seconds; 0 if non-expiring)"},
	} {
		a.APIMetrics[metric.name] = prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: metric.name,
			Help: metric.help,
		}, []string{"hostname"})
		prometheus.MustRegister(a.APIMetrics[metric.name])
	}
}

func (a *AppConfig) produceAPIDataLoop() {
	for {
		log.Printf("produceAPIDataLoop(): getting data")
		var client *tscg.Client
		switch a.AuthMode {
		case AuthOAuth:
			client = &tscg.Client{
				Tailnet: a.TailNetName,
				HTTP: tscg.OAuthConfig{
					ClientID:     a.ClientId,
					ClientSecret: a.ClientSecret,
					Scopes:       []string{"devices:read", "network-logs:read"},
				}.HTTPClient(),
			}
		case AuthAPIKey:
			// The tscg library doesn't (yet) have a high-level helper here in this codebase;
			// we reuse our API key HTTP client.
			client = &tscg.Client{Tailnet: a.TailNetName, HTTP: newAPIKeyHTTPClient(a.APIKey)}
		case AuthLocal:
			// Local mode: query tailscaled via its unix socket and map into metrics.
			st, err := fetchLocalStatus(a.LocalSocketPath)
			if err != nil {
				log.Printf("produceAPIDataLoop(): local status error: %v", err)
				goto sleep
			}
			// Ensure base gauge vecs were registered earlier.
			// Reuse same metric names for parity with central mode.
			// (updateLocalAPIMetrics handles translation.)
			// Clear existing host gauges before re-populating to avoid stale hosts lingering? Not necessary since we set value=1 each loop; stale hosts will retain last value. Future improvement: track and delete.
			// Update metrics directly.
			a.updateLocalAPIMetrics(st)
			goto sleep
		}
		a.updateAPIMetrics(client)
	sleep:
		log.Printf("produceAPIDataLoop(): sleeping for %d secs", a.SleepIntervalSeconds)
		time.Sleep(time.Duration(a.SleepIntervalSeconds) * time.Second)
	}
}

func (a *AppConfig) updateAPIMetrics(client *tscg.Client) {
	ctx := context.Background()
	devices, err := client.Devices().List(ctx)
	if err != nil {
		log.Printf("produceAPIDataLoop() error: %s", err)
		return
	}

	for _, d := range devices {
		// Join & sort tags for deterministic value
		tags := ""
		if len(d.Tags) > 0 {
			cpy := append([]string{}, d.Tags...)
			sort.Strings(cpy)
			tags = strings.Join(cpy, ",")
		}
		a.APIMetrics["tailscale_hosts"].WithLabelValues(
			d.Hostname,
			strconv.FormatBool(d.UpdateAvailable),
			d.OS,
			strconv.FormatBool(d.IsExternal),
			d.User,
			d.ClientVersion,
			tags,
		).Set(1)

		// Helper to safely expose times; zero value => 0
		setTime := func(metric string, t time.Time) {
			v := float64(0)
			if !t.IsZero() {
				v = float64(t.Unix())
			}
			a.APIMetrics[metric].WithLabelValues(d.Hostname).Set(v)
		}
		setTime("tailscale_host_created_timestamp", d.Created.Time)
		setTime("tailscale_host_last_seen_timestamp", d.LastSeen.Time)
		setTime("tailscale_host_expires_timestamp", d.Expires.Time)
	}
}

func (a *AppConfig) addHandlers() {
	http.Handle("/metrics", promhttp.Handler())

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "ok")
	})
}
