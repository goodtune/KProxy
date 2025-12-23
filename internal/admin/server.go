package admin

import (
	"context"
	"embed"
	"fmt"
	"net/http"
	"time"

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
	auth          *AuthService
	rateLimiter   *RateLimiter
	server        *http.Server
	router        *mux.Router
	logger        zerolog.Logger
}

// NewServer creates a new admin server.
func NewServer(cfg Config, store storage.Store, policyEngine *policy.Engine, logger zerolog.Logger) *Server {
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

	s := &Server{
		config:       cfg,
		store:        store,
		policyEngine: policyEngine,
		auth:         auth,
		rateLimiter:  rateLimiter,
		router:       router,
		logger:       logger.With().Str("component", "admin").Logger(),
	}

	// Setup routes
	s.setupRoutes()

	// Create HTTP server
	s.server = &http.Server{
		Addr:         cfg.ListenAddr,
		Handler:      router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
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
	s.router.HandleFunc("/health", s.handleHealth).Methods("GET")

	// Authenticated routes
	authRouter := s.router.PathPrefix("/").Subrouter()
	authRouter.Use(AuthMiddleware(s.auth))

	// Auth endpoints
	authRouter.HandleFunc("/api/auth/logout", s.handleLogout).Methods("POST")
	authRouter.HandleFunc("/api/auth/me", s.handleMe).Methods("GET")
	authRouter.HandleFunc("/api/auth/change-password", s.handleChangePassword).Methods("POST")

	// Static files (will be implemented later with go:embed)
	// authRouter.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.FS(staticFS))))

	// Web UI routes (will be implemented in Phase 5.2)
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

// Start starts the admin HTTP server.
func (s *Server) Start() error {
	s.logger.Info().
		Str("addr", s.config.ListenAddr).
		Msg("Starting admin server")

	go func() {
		if err := s.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
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

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	// Will be implemented in Phase 5.2
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "<html><body><h1>KProxy Admin Dashboard</h1><p>Coming soon...</p></body></html>")
}

// Helper function to write JSON responses.
func writeJSON(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	// In production, you'd use json.Marshal here
	fmt.Fprintf(w, "%v", data)
}

// Helper function to write error responses.
func writeError(w http.ResponseWriter, statusCode int, message string) {
	writeJSON(w, statusCode, ErrorResponse{
		Error:   http.StatusText(statusCode),
		Message: message,
		Code:    statusCode,
	})
}
