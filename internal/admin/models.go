package admin

import (
	"bytes"
	"encoding/json"
	"net/http"
	"time"
)

// LoginRequest represents a login request from the user.
type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// LoginResponse represents the response after a successful login.
type LoginResponse struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
	User      UserInfo  `json:"user"`
}

// UserInfo represents basic user information.
type UserInfo struct {
	ID       string `json:"id"`
	Username string `json:"username"`
}

// ChangePasswordRequest represents a password change request.
type ChangePasswordRequest struct {
	OldPassword string `json:"old_password"`
	NewPassword string `json:"new_password"`
}

// ErrorResponse represents an API error response.
type ErrorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message,omitempty"`
	Code    int    `json:"code"`
}

// SuccessResponse represents a generic success response.
type SuccessResponse struct {
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

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
