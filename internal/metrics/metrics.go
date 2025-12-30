package metrics

import (
	"net"
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/zerolog"
)

var (
	// Request metrics
	RequestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "kproxy_requests_total",
			Help: "Total number of HTTP/HTTPS requests processed",
		},
		[]string{"device", "host", "action", "method"},
	)

	RequestDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "kproxy_request_duration_seconds",
			Help:    "Request duration in seconds",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"device", "action"},
	)

	// DNS metrics
	DNSQueriesTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "kproxy_dns_queries_total",
			Help: "Total DNS queries received",
		},
		[]string{"device", "action", "query_type"},
	)

	DNSQueryDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "kproxy_dns_query_duration_seconds",
			Help:    "DNS query duration in seconds",
			Buckets: []float64{.001, .005, .01, .025, .05, .1, .25, .5, 1},
		},
		[]string{"action"},
	)

	DNSUpstreamErrors = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "kproxy_dns_upstream_errors_total",
			Help: "DNS upstream query errors",
		},
		[]string{"upstream"},
	)

	// TLS/Certificate metrics
	CertificatesGenerated = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "kproxy_certificates_generated_total",
			Help: "Total certificates generated",
		},
	)

	CertificateCacheHits = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "kproxy_certificate_cache_hits_total",
			Help: "Certificate cache hits",
		},
	)

	CertificateCacheMisses = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "kproxy_certificate_cache_misses_total",
			Help: "Certificate cache misses",
		},
	)

	// Policy metrics
	BlockedRequests = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "kproxy_blocked_requests_total",
			Help: "Total blocked requests",
		},
		[]string{"device", "reason"},
	)

	// Usage metrics
	UsageMinutesConsumed = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "kproxy_usage_minutes_consumed_total",
			Help: "Total usage minutes consumed",
		},
		[]string{"device", "category"},
	)

	// Connection metrics
	ActiveConnections = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "kproxy_active_connections",
			Help: "Number of active connections",
		},
	)

	// DHCP metrics
	DHCPRequestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "kproxy_dhcp_requests_total",
			Help: "Total DHCP requests received",
		},
		[]string{"type"},
	)

	DHCPLeasesActive = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "kproxy_dhcp_leases_active",
			Help: "Number of active DHCP leases",
		},
	)
)

func init() {
	// Register all metrics
	prometheus.MustRegister(
		RequestsTotal,
		RequestDuration,
		DNSQueriesTotal,
		DNSQueryDuration,
		DNSUpstreamErrors,
		CertificatesGenerated,
		CertificateCacheHits,
		CertificateCacheMisses,
		BlockedRequests,
		UsageMinutesConsumed,
		ActiveConnections,
		DHCPRequestsTotal,
		DHCPLeasesActive,
	)
}

// Server is the metrics HTTP server
type Server struct {
	server   *http.Server
	logger   zerolog.Logger
	listener net.Listener // Optional pre-created listener (for systemd socket activation)
}

// NewServer creates a new metrics server
func NewServer(addr string, logger zerolog.Logger) *Server {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	})

	return &Server{
		server: &http.Server{
			Addr:    addr,
			Handler: mux,
		},
		logger: logger.With().Str("component", "metrics").Logger(),
	}
}

// SetListener sets a pre-created listener for systemd socket activation
func (s *Server) SetListener(ln net.Listener) {
	s.listener = ln
}

// Start starts the metrics server
func (s *Server) Start() error {
	s.logger.Info().Str("addr", s.server.Addr).Msg("Starting metrics server")
	go func() {
		var err error
		if s.listener != nil {
			// Use systemd socket-activated listener
			s.logger.Debug().Msg("Using systemd socket-activated metrics listener")
			err = s.server.Serve(s.listener)
		} else {
			// Create and bind listener ourselves
			err = s.server.ListenAndServe()
		}
		if err != nil && err != http.ErrServerClosed {
			s.logger.Error().Err(err).Msg("Metrics server error")
		}
	}()
	return nil
}

// Stop stops the metrics server
func (s *Server) Stop() error {
	s.logger.Info().Msg("Stopping metrics server")
	return s.server.Close()
}
