package admin

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog"
)

// contextKey is a custom type for context keys to avoid collisions.
type contextKey string

const (
	// ContextKeyUserID is the context key for user ID.
	ContextKeyUserID contextKey = "user_id"

	// ContextKeyUsername is the context key for username.
	ContextKeyUsername contextKey = "username"

	// ContextKeySession is the context key for session ID.
	ContextKeySession contextKey = "session_id"
)

// AuthMiddleware creates middleware for JWT authentication.
func AuthMiddleware(auth *AuthService) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Extract token from Authorization header
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				// Try to get token from cookie
				cookie, err := r.Cookie("admin_token")
				if err != nil {
					http.Error(w, "Unauthorized", http.StatusUnauthorized)
					return
				}
				authHeader = "Bearer " + cookie.Value
			}

			// Extract token
			parts := strings.Split(authHeader, " ")
			if len(parts) != 2 || parts[0] != "Bearer" {
				http.Error(w, "Invalid authorization header", http.StatusUnauthorized)
				return
			}

			token := parts[1]

			// Validate token
			claims, err := auth.ValidateToken(token)
			if err != nil {
				http.Error(w, "Invalid token", http.StatusUnauthorized)
				return
			}

			// Get or create session from token
			// Note: In production, you'd want to manage sessions more carefully
			sessionID := r.Header.Get("X-Session-ID")
			if sessionID == "" {
				// Try to get from cookie
				cookie, _ := r.Cookie("admin_session")
				if cookie != nil {
					sessionID = cookie.Value
				}
			}

			// Refresh session if it exists
			if sessionID != "" {
				_ = auth.RefreshSession(sessionID)
				// Ignore errors - if session refresh fails, we continue with token-based auth
			}

			// Add user info to context
			ctx := r.Context()
			ctx = context.WithValue(ctx, ContextKeyUserID, claims.UserID)
			ctx = context.WithValue(ctx, ContextKeyUsername, claims.Username)
			if sessionID != "" {
				ctx = context.WithValue(ctx, ContextKeySession, sessionID)
			}

			// Call next handler
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// LoggingMiddleware creates middleware for logging HTTP requests.
func LoggingMiddleware(logger zerolog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()

			// Create response writer wrapper to capture status code
			wrapped := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

			// Call next handler
			next.ServeHTTP(wrapped, r)

			// Log request
			duration := time.Since(start)
			logger.Info().
				Str("method", r.Method).
				Str("path", r.URL.Path).
				Str("remote_addr", r.RemoteAddr).
				Int("status", wrapped.statusCode).
				Dur("duration", duration).
				Msg("Admin request")
		})
	}
}

// responseWriter wraps http.ResponseWriter to capture the status code.
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (w *responseWriter) WriteHeader(statusCode int) {
	w.statusCode = statusCode
	w.ResponseWriter.WriteHeader(statusCode)
}

// RateLimiter implements a simple token bucket rate limiter.
type RateLimiter struct {
	requests map[string]*bucket
	mu       sync.RWMutex
	rate     int           // requests per window
	window   time.Duration // time window
}

type bucket struct {
	tokens    int
	lastReset time.Time
}

// NewRateLimiter creates a new rate limiter.
func NewRateLimiter(requestsPerWindow int, window time.Duration) *RateLimiter {
	limiter := &RateLimiter{
		requests: make(map[string]*bucket),
		rate:     requestsPerWindow,
		window:   window,
	}

	// Start cleanup goroutine
	go limiter.cleanup()

	return limiter
}

// Allow checks if a request from the given identifier is allowed.
func (rl *RateLimiter) Allow(identifier string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()

	// Get or create bucket
	b, exists := rl.requests[identifier]
	if !exists {
		rl.requests[identifier] = &bucket{
			tokens:    rl.rate - 1,
			lastReset: now,
		}
		return true
	}

	// Reset bucket if window has passed
	if now.Sub(b.lastReset) > rl.window {
		b.tokens = rl.rate - 1
		b.lastReset = now
		return true
	}

	// Check if tokens available
	if b.tokens > 0 {
		b.tokens--
		return true
	}

	return false
}

// cleanup periodically removes old buckets.
func (rl *RateLimiter) cleanup() {
	ticker := time.NewTicker(rl.window * 2)
	defer ticker.Stop()

	for range ticker.C {
		rl.mu.Lock()
		now := time.Now()
		for id, b := range rl.requests {
			if now.Sub(b.lastReset) > rl.window*2 {
				delete(rl.requests, id)
			}
		}
		rl.mu.Unlock()
	}
}

// RateLimitMiddleware creates middleware for rate limiting.
func RateLimitMiddleware(limiter *RateLimiter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Use IP address as identifier
			identifier := r.RemoteAddr

			// For authenticated requests, use username if available
			if username := r.Context().Value(ContextKeyUsername); username != nil {
				if usernameStr, ok := username.(string); ok {
					identifier = "user:" + usernameStr
				}
			}

			if !limiter.Allow(identifier) {
				http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// CORSMiddleware creates middleware for CORS support.
func CORSMiddleware(allowedOrigins []string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")

			// Check if origin is allowed
			allowed := false
			for _, allowedOrigin := range allowedOrigins {
				if allowedOrigin == "*" || allowedOrigin == origin {
					allowed = true
					break
				}
			}

			if allowed {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
				w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, X-Session-ID")
				w.Header().Set("Access-Control-Allow-Credentials", "true")
			}

			// Handle preflight requests
			if r.Method == "OPTIONS" {
				w.WriteHeader(http.StatusNoContent)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// GetUserIDFromContext extracts the user ID from the request context.
func GetUserIDFromContext(ctx context.Context) (string, bool) {
	userID, ok := ctx.Value(ContextKeyUserID).(string)
	return userID, ok
}

// GetUsernameFromContext extracts the username from the request context.
func GetUsernameFromContext(ctx context.Context) (string, bool) {
	username, ok := ctx.Value(ContextKeyUsername).(string)
	return username, ok
}

// GetSessionFromContext extracts the session ID from the request context.
func GetSessionFromContext(ctx context.Context) (string, bool) {
	sessionID, ok := ctx.Value(ContextKeySession).(string)
	return sessionID, ok
}
