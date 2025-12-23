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
	ServerName      string   // Hostname for TLS certificate generation
	JWTSecret       string
	TokenExpiration time.Duration
	RateLimit       int
	RateLimitWindow time.Duration
	AllowedOrigins  []string
}

// Server represents the admin HTTP server.
type Server struct {
	config        Config
	store         storage.Store
	policyEngine  *policy.Engine
	ca            *ca.CA
	auth          *AuthService
	rateLimiter   *RateLimiter
	server        *http.Server
	router        *mux.Router
	templates     *template.Template
	logger        zerolog.Logger
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

	// API routes will be added in later phases:
	// - Phase 5.3: Device management
	// - Phase 5.4: Profile management
	// - Phase 5.5: Rules management
	// - Phase 5.6: Logs & monitoring
	// - Phase 5.7: Usage & sessions
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
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `{"status":"ok","active_sessions":%d}`, s.auth.GetActiveSessions())
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

// Helper function to write JSON responses.
func writeJSON(w http.ResponseWriter, statusCode int, data interface{}) {
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(data); err != nil {
		http.Error(w, `{"error":"Internal Server Error","message":"Failed to encode response"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_, _ = w.Write(buf.Bytes())
}

// Helper function to write error responses.
func writeError(w http.ResponseWriter, statusCode int, message string) {
	writeJSON(w, statusCode, ErrorResponse{
		Error:   http.StatusText(statusCode),
		Message: message,
		Code:    statusCode,
	})
}
