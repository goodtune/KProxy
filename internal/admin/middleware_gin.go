package admin

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog"
)

// AuthMiddlewareGin creates Gin middleware for JWT authentication.
func AuthMiddlewareGin(auth *AuthService) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		// Extract token from Authorization header
		authHeader := ctx.GetHeader("Authorization")
		if authHeader == "" {
			// Try to get token from cookie
			cookie, err := ctx.Cookie("admin_token")
			if err != nil {
				ctx.JSON(http.StatusUnauthorized, gin.H{
					"error":   "unauthorized",
					"message": "Missing authentication token",
				})
				ctx.Abort()
				return
			}
			authHeader = "Bearer " + cookie
		}

		// Extract token
		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			ctx.JSON(http.StatusUnauthorized, gin.H{
				"error":   "unauthorized",
				"message": "Invalid authorization header",
			})
			ctx.Abort()
			return
		}

		token := parts[1]

		// Validate token
		claims, err := auth.ValidateToken(token)
		if err != nil {
			ctx.JSON(http.StatusUnauthorized, gin.H{
				"error":   "unauthorized",
				"message": "Invalid or expired token",
			})
			ctx.Abort()
			return
		}

		// Get session ID from cookie
		sessionID, _ := ctx.Cookie("admin_session")

		// Refresh session if it exists
		if sessionID != "" {
			_ = auth.RefreshSession(sessionID)
			// Ignore errors - if session refresh fails, we continue with token-based auth
		}

		// Add user info to context
		ctx.Set("user_id", claims.UserID)
		ctx.Set("username", claims.Username)
		if sessionID != "" {
			ctx.Set("session_id", sessionID)
		}

		ctx.Next()
	}
}

// LoggingMiddlewareGin creates Gin middleware for request logging.
func LoggingMiddlewareGin(logger zerolog.Logger) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		// Process request
		ctx.Next()

		// Log after processing
		logger.Info().
			Str("method", ctx.Request.Method).
			Str("path", ctx.Request.URL.Path).
			Str("remote_addr", ctx.ClientIP()).
			Int("status", ctx.Writer.Status()).
			Int("size", ctx.Writer.Size()).
			Msg("Admin request")
	}
}

// RateLimitMiddlewareGin creates Gin middleware for rate limiting.
func RateLimitMiddlewareGin(limiter *RateLimiter) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		// Use IP address as identifier
		identifier := ctx.ClientIP()

		// For authenticated requests, use username if available
		if username, exists := ctx.Get("username"); exists {
			if usernameStr, ok := username.(string); ok {
				identifier = "user:" + usernameStr
			}
		}

		if !limiter.Allow(identifier) {
			ctx.JSON(http.StatusTooManyRequests, gin.H{
				"error":   "rate_limit_exceeded",
				"message": "Too many requests, please try again later",
			})
			ctx.Abort()
			return
		}

		ctx.Next()
	}
}

// CORSMiddlewareGin creates Gin middleware for CORS support.
func CORSMiddlewareGin(allowedOrigins []string) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		origin := ctx.GetHeader("Origin")

		// Check if origin is allowed
		allowed := false
		for _, allowedOrigin := range allowedOrigins {
			if allowedOrigin == "*" || allowedOrigin == origin {
				allowed = true
				break
			}
		}

		if allowed {
			ctx.Writer.Header().Set("Access-Control-Allow-Origin", origin)
			ctx.Writer.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			ctx.Writer.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, X-Session-ID")
			ctx.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
		}

		// Handle preflight requests
		if ctx.Request.Method == "OPTIONS" {
			ctx.AbortWithStatus(http.StatusNoContent)
			return
		}

		ctx.Next()
	}
}
