// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"sync/atomic"
	"time"

	"github.com/go-net-health/endpoint"
)

// What a supervisor asks, on a listener of its own:
//
//	metrics { listen = "127.0.0.1:9100" }
//
//	/healthz  the process answers: a liveness probe restarts it when not
//	/readyz   every protocol is bound and a generation is serving; 503, and
//	          why, while it starts, while a change is being applied, and
//	          while it stops
//	/metrics  Prometheus text format
//
// ⛔ No metric carries a share's name, or a person's. WebDAV answers 404 for
// a share somebody may not use, so that its existence is not confirmed; a
// scrape that listed every share would confirm it to whoever can reach this
// port. The labels are protocols and outcomes, which the configuration's
// serve blocks already say to anybody who can connect.

// serverStats is what the admin API did, counted where it happens.
type serverStats struct {
	started time.Time
	applied atomic.Uint64
	refused atomic.Uint64
	// rpcs counts admin calls by method and status code; filled in by the
	// gRPC layer, when there is one.
	rpcs func(w *endpoint.Writer)
}

// shareCounts is how many of the shares served the admin API defined, and
// how many are taken offline.
func (s *server) shareCounts() (api, offline int) {
	if m := s.mgr.Load(); m != nil {
		return int(m.servedAPI.Load()), int(m.offline.Load())
	}
	return 0, 0
}

// readiness says whether the server should receive traffic, and when not,
// why -- in the /readyz body, where an operator reads it.
func (s *server) readiness() error {
	if !s.ready.Load() {
		return errors.New("not serving: starting, applying a change, or stopping")
	}
	return nil
}

// collect writes this server's families.
func (s *server) collect(w *endpoint.Writer) {
	w.Gauge("fileshare_start_time_seconds", "When this process started, in seconds since the epoch.",
		endpoint.S(float64(s.stats.started.Unix())))
	w.Gauge("fileshare_generation", "How many lists of shares have been served since the start.",
		endpoint.S(float64(s.generationNumber())))
	api, offline := s.shareCounts()
	total := len(s.currentShares())
	w.Gauge("fileshare_shares", "Shares being served, by where they are defined.",
		endpoint.S(float64(total-api), endpoint.L("origin", "config")),
		endpoint.S(float64(api), endpoint.L("origin", "api")))
	w.Gauge("fileshare_shares_disabled", "Shares defined and taken offline through the admin API.",
		endpoint.S(float64(offline)))
	w.Counter("fileshare_admin_changes_total", "Changes asked of the admin API, by outcome.",
		endpoint.S(float64(s.stats.applied.Load()), endpoint.L("result", "applied")),
		endpoint.S(float64(s.stats.refused.Load()), endpoint.L("result", "refused")))

	s.runMu.Lock()
	feeds := s.feeds
	s.runMu.Unlock()
	accepted := make([]endpoint.Sample, 0, len(feeds))
	open := make([]endpoint.Sample, 0, len(feeds))
	for _, f := range feeds {
		l := endpoint.L("protocol", f.proto)
		accepted = append(accepted, endpoint.S(float64(f.accepted.Load()), l))
		open = append(open, endpoint.S(float64(f.open.Load()), l))
	}
	w.Counter("fileshare_connections_accepted_total", "Connections accepted, by protocol.", accepted...)
	w.Gauge("fileshare_connections_open", "Connections open now, by protocol.", open...)
	if s.stats.rpcs != nil {
		s.stats.rpcs(w)
	}
}

// startControl starts the metrics and admin listeners the configuration
// names, and returns what stops them.
func (s *server) startControl(ctx context.Context, cfg *config) (func(), error) {
	var stops []func()
	stopAll := func() {
		for i := len(stops) - 1; i >= 0; i-- {
			stops[i]()
		}
	}
	// The admin API first: it registers the collector of its own calls, and
	// the metrics listener must not be reading that field while it is set.
	if t := cfg.TLS; t != nil && t.ACME != nil && t.ACME.HTTPChallenge != "" {
		stop, err := s.serveHTTPChallenge(t.ACME.HTTPChallenge)
		if err != nil {
			stopAll()
			return nil, fmt.Errorf("tls: http_challenge: %w", err)
		}
		stops = append(stops, stop)
	}
	if cfg.Admin != nil {
		stop, err := startAdmin(ctx, s, cfg)
		if err != nil {
			return nil, fmt.Errorf("admin: %w", err)
		}
		stops = append(stops, stop)
	}
	if m := cfg.Metrics; m != nil {
		stop, err := s.serveMetrics(m)
		if err != nil {
			stopAll()
			return nil, fmt.Errorf("metrics: %w", err)
		}
		stops = append(stops, stop)
	}
	return stopAll, nil
}

// serveHTTPChallenge answers ACME's http-01 on the address the CA's port 80
// reaches, and redirects everything else to HTTPS.
func (s *server) serveHTTPChallenge(addr string) (func(), error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	hs := &http.Server{Handler: s.certs.HTTPHandler(nil), ReadHeaderTimeout: 10 * time.Second}
	go hs.Serve(ln)
	fmt.Fprintf(s.out, "%-6s on %s — ACME http-01\n", "acme", ln.Addr())
	return func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		hs.Shutdown(ctx)
	}, nil
}

func (s *server) serveMetrics(m *metricsBlock) (func(), error) {
	network, addr, err := metricsNetwork(m.Listen)
	if err != nil {
		return nil, err
	}
	if network == "unix" {
		// Only a file that IS a socket is taken over; anything else at that
		// path is somebody's, and an error.
		if fi, err := os.Lstat(addr); err == nil && fi.Mode()&os.ModeSocket != 0 {
			if c, err := net.Dial("unix", addr); err == nil {
				c.Close()
				return nil, fmt.Errorf("%s is in use by a running process", addr)
			}
			os.Remove(addr)
		}
	}
	ln, err := net.Listen(network, addr)
	if err != nil {
		return nil, err
	}
	h := endpoint.Handler(endpoint.Options{
		Ready: s.readiness,
		Collectors: []endpoint.Collector{
			endpoint.BuildInfo("fileshare"),
			endpoint.GoRuntime,
			s.collect,
		},
	})
	hs := &http.Server{Handler: h, ReadHeaderTimeout: 10 * time.Second}
	go hs.Serve(ln)
	fmt.Fprintf(s.out, "%-6s on %s — /healthz /readyz /metrics\n", "health", ln.Addr())
	return func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		hs.Shutdown(ctx)
	}, nil
}
