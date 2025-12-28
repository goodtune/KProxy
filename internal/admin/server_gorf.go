package admin

import (
	"context"
	"crypto/tls"
	
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/goodtune/kproxy/internal/ca"
	"github.com/goodtune/kproxy/internal/policy"
	"github.com/goodtune/kproxy/internal/storage"
	"github.com/goodtune/kproxy/internal/usage"
	"github.com/rs/zerolog"
)

// GorfServer represents the gorf-based admin HTTP server.
type GorfServer struct {
	config       Config
	store        storage.Store
	policyEngine *policy.Engine
	usageTracker *usage.Tracker
	ca           *ca.CA
	auth         *AuthService
	server       *http.Server
	router       *gin.Engine
	logger       zerolog.Logger
}

// NewGorfServer creates a new gorf-based admin server.
func NewGorfServer(
	cfg Config,
	store storage.Store,
	policyEngine *policy.Engine,
	usageTracker *usage.Tracker,
	certificateAuthority *ca.CA,
	logger zerolog.Logger,
) *GorfServer {
	// Set Gin mode
	if logger.GetLevel() == zerolog.DebugLevel {
		gin.SetMode(gin.DebugMode)
	} else {
		gin.SetMode(gin.ReleaseMode)
	}

	// Create auth service
	auth := NewAuthService(store.AdminUsers(), cfg.JWTSecret, cfg.TokenExpiration)

	// Start session cleanup
	auth.StartSessionCleanup(15 * time.Minute)

	// Set admin dependencies
	adminDeps := &AdminDeps{
		Store:          store,
		Auth:           auth,
		PolicyEngine:   policyEngine,
		UsageTracker:   usageTracker,
		Logger:         logger.With().Str("component", "admin").Logger(),
		AllowedOrigins: cfg.AllowedOrigins,
	}

	// Set Gin to release mode (suppress debug output)
	gin.SetMode(gin.ReleaseMode)

	// Create Gin router without default middleware (we use custom JSON logging)
	router := gin.New()

	// Add recovery middleware (handles panics)
	router.Use(gin.Recovery())

	// Setup routes directly
	SetupGorfRoutes(router, adminDeps)

	s := &GorfServer{
		config:       cfg,
		store:        store,
		policyEngine: policyEngine,
		usageTracker: usageTracker,
		ca:           certificateAuthority,
		auth:         auth,
		router:       router,
		logger:       logger.With().Str("component", "admin").Logger(),
	}

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

// Start starts the admin server.
func (s *GorfServer) Start() error {
	go func() {
		s.logger.Info().Str("addr", s.config.ListenAddr).Msg("Starting admin server")
		if err := s.server.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			s.logger.Fatal().Err(err).Msg("Admin server failed")
		}
	}()
	return nil
}

// Stop gracefully stops the admin server.
func (s *GorfServer) Stop() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	s.logger.Info().Msg("Stopping admin server")
	return s.server.Shutdown(ctx)
}
