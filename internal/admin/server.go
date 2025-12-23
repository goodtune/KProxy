package admin

import (
	"bytes"
	"context"
	"crypto/tls"
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"time"

	"github.com/goodtune/kproxy/internal/admin/api"
	"github.com/goodtune/kproxy/internal/ca"
	"github.com/goodtune/kproxy/internal/policy"
	"github.com/goodtune/kproxy/internal/storage"
	"github.com/gorilla/mux"
	"github.com/rs/zerolog"
)

//go:embed static
var staticFS embed.FS

// Config holds the admin server configuration.
type Config struct {
	ListenAddr      string
	ServerName      string // Hostname for TLS certificate generation
	JWTSecret       string
	TokenExpiration time.Duration
	RateLimit       int
	RateLimitWindow time.Duration
	AllowedOrigins  []string
}

// Server represents the admin HTTP server.
type Server struct {
	config       Config
	store        storage.Store
	policyEngine *policy.Engine
	ca           *ca.CA
	auth         *AuthService
	rateLimiter  *RateLimiter
	server       *http.Server
	router       *mux.Router
	templates    *template.Template
	logger       zerolog.Logger
}

// NewServer creates a new admin server.
func NewServer(cfg Config, store storage.Store, policyEngine *policy.Engine, certificateAuthority *ca.CA, logger zerolog.Logger) *Server {
	// Create auth service
	auth := NewAuthService(store.AdminUsers(), cfg.JWTSecret, cfg.TokenExpiration)

	// Start session cleanup
	auth.StartSessionCleanup(15 * time.Minute)

	// Create rate limiter
	rateLimit := cfg.RateLimit
	if rateLimit == 0 {
		rateLimit = 100 // Default: 100 requests per minute
	}
	rateLimitWindow := cfg.RateLimitWindow
	if rateLimitWindow == 0 {
		rateLimitWindow = time.Minute
	}
	rateLimiter := NewRateLimiter(rateLimit, rateLimitWindow)

	// Create router
	router := mux.NewRouter()

	// Parse templates
	tmpl, err := template.ParseFS(staticFS, "static/templates/*.html")
	if err != nil {
		logger.Error().Err(err).Msg("Failed to parse templates")
		tmpl = template.New("fallback")
	}

	s := &Server{
		config:       cfg,
		store:        store,
		policyEngine: policyEngine,
		ca:           certificateAuthority,
		auth:         auth,
		rateLimiter:  rateLimiter,
		router:       router,
		templates:    tmpl,
		logger:       logger.With().Str("component", "admin").Logger(),
	}

	// Setup routes
	s.setupRoutes()

	// Create HTTPS server with TLS config
	s.server = &http.Server{
		Addr:         cfg.ListenAddr,
		Handler:      router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
		TLSConfig: &tls.Config{
			GetCertificate: certificateAuthority.GetCertificate,
			MinVersion:     tls.VersionTLS12,
		},
	}

	return s
}

// setupRoutes configures all HTTP routes.
func (s *Server) setupRoutes() {
	// Apply global middleware
	s.router.Use(LoggingMiddleware(s.logger))
	s.router.Use(RateLimitMiddleware(s.rateLimiter))

	if len(s.config.AllowedOrigins) > 0 {
		s.router.Use(CORSMiddleware(s.config.AllowedOrigins))
	}

	// Public routes (no auth required)
	s.router.HandleFunc("/api/auth/login", s.handleLogin).Methods("POST", "OPTIONS")
	s.router.HandleFunc("/admin/login", s.handleLoginPage).Methods("GET")
	s.router.HandleFunc("/health", s.handleHealth).Methods("GET")

	// Static files
	staticSub, err := fs.Sub(staticFS, "static")
	if err == nil {
		s.router.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.FS(staticSub))))
	}

	// Authenticated routes
	authRouter := s.router.PathPrefix("/").Subrouter()
	authRouter.Use(AuthMiddleware(s.auth))

	// Auth endpoints
	authRouter.HandleFunc("/api/auth/logout", s.handleLogout).Methods("POST")
	authRouter.HandleFunc("/api/auth/me", s.handleMe).Methods("GET")
	authRouter.HandleFunc("/api/auth/change-password", s.handleChangePassword).Methods("POST")

	// Web UI routes
	authRouter.HandleFunc("/", s.handleDashboard).Methods("GET")
	authRouter.HandleFunc("/admin/dashboard", s.handleDashboard).Methods("GET")
	authRouter.HandleFunc("/admin/devices", s.handleDevicesPage).Methods("GET")
	authRouter.HandleFunc("/admin/profiles", s.handleProfilesPage).Methods("GET")
	authRouter.HandleFunc("/admin/logs", s.handleLogsPage).Methods("GET")
	authRouter.HandleFunc("/admin/sessions", s.handleSessionsPage).Methods("GET")

	// Device API routes (Phase 5.3)
	deviceHandler := api.NewDeviceHandler(s.store.Devices(), s.logger)
	authRouter.HandleFunc("/api/devices", deviceHandler.List).Methods("GET")
	authRouter.HandleFunc("/api/devices", deviceHandler.Create).Methods("POST")
	authRouter.HandleFunc("/api/devices/{id}", deviceHandler.Get).Methods("GET")
	authRouter.HandleFunc("/api/devices/{id}", deviceHandler.Update).Methods("PUT")
	authRouter.HandleFunc("/api/devices/{id}", deviceHandler.Delete).Methods("DELETE")

	// Profile API routes (Phase 5.4)
	profileHandler := api.NewProfileHandler(s.store.Profiles(), s.logger)
	authRouter.HandleFunc("/api/profiles", profileHandler.List).Methods("GET")
	authRouter.HandleFunc("/api/profiles", profileHandler.Create).Methods("POST")
	authRouter.HandleFunc("/api/profiles/{id}", profileHandler.Get).Methods("GET")
	authRouter.HandleFunc("/api/profiles/{id}", profileHandler.Update).Methods("PUT")
	authRouter.HandleFunc("/api/profiles/{id}", profileHandler.Delete).Methods("DELETE")

	// Rules API routes (Phase 5.5)
	rulesHandler := api.NewRulesHandler(
		s.store.Rules(),
		s.store.TimeRules(),
		s.store.UsageLimits(),
		s.store.BypassRules(),
		s.policyEngine,
		s.logger,
	)
	// Regular rules
	authRouter.HandleFunc("/api/profiles/{profileID}/rules", rulesHandler.ListRules).Methods("GET")
	authRouter.HandleFunc("/api/profiles/{profileID}/rules", rulesHandler.CreateRule).Methods("POST")
	authRouter.HandleFunc("/api/profiles/{profileID}/rules/{ruleID}", rulesHandler.GetRule).Methods("GET")
	authRouter.HandleFunc("/api/profiles/{profileID}/rules/{ruleID}", rulesHandler.UpdateRule).Methods("PUT")
	authRouter.HandleFunc("/api/profiles/{profileID}/rules/{ruleID}", rulesHandler.DeleteRule).Methods("DELETE")

	// Time rules
	authRouter.HandleFunc("/api/profiles/{profileID}/time-rules", rulesHandler.ListTimeRules).Methods("GET")
	authRouter.HandleFunc("/api/profiles/{profileID}/time-rules", rulesHandler.CreateTimeRule).Methods("POST")
	authRouter.HandleFunc("/api/profiles/{profileID}/time-rules/{ruleID}", rulesHandler.DeleteTimeRule).Methods("DELETE")

	// Usage limits
	authRouter.HandleFunc("/api/profiles/{profileID}/usage-limits", rulesHandler.ListUsageLimits).Methods("GET")
	authRouter.HandleFunc("/api/profiles/{profileID}/usage-limits", rulesHandler.CreateUsageLimit).Methods("POST")
	authRouter.HandleFunc("/api/profiles/{profileID}/usage-limits/{limitID}", rulesHandler.DeleteUsageLimit).Methods("DELETE")

	// Bypass rules (global, not profile-specific)
	authRouter.HandleFunc("/api/bypass-rules", rulesHandler.ListBypassRules).Methods("GET")
	authRouter.HandleFunc("/api/bypass-rules", rulesHandler.CreateBypassRule).Methods("POST")
	authRouter.HandleFunc("/api/bypass-rules/{id}", rulesHandler.DeleteBypassRule).Methods("DELETE")

	// Logs API routes (Phase 5.6)
	logsHandler := api.NewLogsHandler(s.store.Logs(), s.logger)
	authRouter.HandleFunc("/api/logs/requests", logsHandler.QueryRequestLogs).Methods("GET")
	authRouter.HandleFunc("/api/logs/dns", logsHandler.QueryDNSLogs).Methods("GET")
	authRouter.HandleFunc("/api/logs/requests/{days}", logsHandler.DeleteOldRequestLogs).Methods("DELETE")
	authRouter.HandleFunc("/api/logs/dns/{days}", logsHandler.DeleteOldDNSLogs).Methods("DELETE")

	// Sessions and Usage API routes (Phase 5.7)
	sessionsHandler := api.NewSessionsHandler(s.store.Usage(), s.logger)
	authRouter.HandleFunc("/api/sessions", sessionsHandler.ListActiveSessions).Methods("GET")
	authRouter.HandleFunc("/api/sessions/{id}", sessionsHandler.GetSession).Methods("GET")
	authRouter.HandleFunc("/api/sessions/{id}", sessionsHandler.TerminateSession).Methods("DELETE")
	authRouter.HandleFunc("/api/usage/today", sessionsHandler.GetTodayUsage).Methods("GET")
	authRouter.HandleFunc("/api/usage/{date}", sessionsHandler.GetDailyUsage).Methods("GET")

	// API routes will be added in later phases:
	// - Phase 5.8: Dashboard statistics
	// - Phase 5.9: System control
}

// Start starts the admin HTTPS server.
func (s *Server) Start() error {
	s.logger.Info().
		Str("addr", s.config.ListenAddr).
		Str("servername", s.config.ServerName).
		Msg("Starting admin server (HTTPS)")

	go func() {
		// Empty strings tell ListenAndServeTLS to use the TLSConfig.GetCertificate callback
		if err := s.server.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			s.logger.Error().Err(err).Msg("Admin server error")
		}
	}()

	return nil
}

// Stop gracefully stops the admin HTTP server.
func (s *Server) Stop() error {
	s.logger.Info().Msg("Stopping admin server")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := s.server.Shutdown(ctx); err != nil {
		return fmt.Errorf("admin server shutdown: %w", err)
	}

	return nil
}

// Placeholder handlers (will be fully implemented in Phase 5.2)

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	WriteJSON(w, http.StatusOK, map[string]interface{}{
		"status":          "ok",
		"active_sessions": s.auth.GetActiveSessions(),
	})
}

func (s *Server) handleLoginPage(w http.ResponseWriter, r *http.Request) {
	data := map[string]interface{}{
		"Title":  "Login",
		"PageID": "login",
	}
	if err := s.templates.ExecuteTemplate(w, "layout.html", data); err != nil {
		s.logger.Error().Err(err).Msg("Failed to render login template")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	data := map[string]interface{}{
		"Title":  "Dashboard",
		"PageID": "dashboard",
	}
	if err := s.templates.ExecuteTemplate(w, "layout.html", data); err != nil {
		s.logger.Error().Err(err).Msg("Failed to render dashboard template")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

func (s *Server) handleDevicesPage(w http.ResponseWriter, r *http.Request) {
	data := map[string]interface{}{
		"Title":  "Devices",
		"PageID": "devices",
	}
	if err := s.templates.ExecuteTemplate(w, "layout.html", data); err != nil {
		s.logger.Error().Err(err).Msg("Failed to render devices template")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

func (s *Server) handleProfilesPage(w http.ResponseWriter, r *http.Request) {
	data := map[string]interface{}{
		"Title":  "Profiles",
		"PageID": "profiles",
	}
	if err := s.templates.ExecuteTemplate(w, "layout.html", data); err != nil {
		s.logger.Error().Err(err).Msg("Failed to render profiles template")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

func (s *Server) handleLogsPage(w http.ResponseWriter, r *http.Request) {
	data := map[string]interface{}{
		"Title":  "Logs",
		"PageID": "logs",
	}
	if err := s.templates.ExecuteTemplate(w, "layout.html", data); err != nil {
		s.logger.Error().Err(err).Msg("Failed to render logs template")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

func (s *Server) handleSessionsPage(w http.ResponseWriter, r *http.Request) {
	data := map[string]interface{}{
		"Title":  "Sessions",
		"PageID": "sessions",
	}
	if err := s.templates.ExecuteTemplate(w, "layout.html", data); err != nil {
		s.logger.Error().Err(err).Msg("Failed to render sessions template")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

// WriteJSON writes a JSON response (exported for use in api subpackage).
func WriteJSON(w http.ResponseWriter, statusCode int, data interface{}) {
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(data); err != nil {
		http.Error(w, `{"error":"Internal Server Error","message":"Failed to encode response"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_, _ = w.Write(buf.Bytes())
}

// WriteError writes an error response (exported for use in api subpackage).
func WriteError(w http.ResponseWriter, statusCode int, message string) {
	WriteJSON(w, statusCode, ErrorResponse{
		Error:   http.StatusText(statusCode),
		Message: message,
		Code:    statusCode,
	})
}

func writeError(w http.ResponseWriter, statusCode int, message string) {
	WriteError(w, statusCode, message)
}
