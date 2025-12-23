package admin

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/goodtune/kproxy/internal/storage"
	"golang.org/x/crypto/bcrypt"
)

const (
	// DefaultTokenExpiration is the default expiration time for JWT tokens.
	DefaultTokenExpiration = 24 * time.Hour

	// BcryptCost is the cost factor for bcrypt password hashing.
	BcryptCost = 12
)

var (
	// ErrInvalidCredentials is returned when login credentials are invalid.
	ErrInvalidCredentials = errors.New("invalid credentials")

	// ErrInvalidToken is returned when a JWT token is invalid.
	ErrInvalidToken = errors.New("invalid token")

	// ErrSessionNotFound is returned when a session is not found.
	ErrSessionNotFound = errors.New("session not found")

	// ErrSessionExpired is returned when a session has expired.
	ErrSessionExpired = errors.New("session expired")
)

// Claims represents the JWT claims for an admin user.
type Claims struct {
	UserID   string `json:"user_id"`
	Username string `json:"username"`
	jwt.RegisteredClaims
}

// Session represents an active admin session.
type Session struct {
	ID           string
	UserID       string
	Username     string
	CreatedAt    time.Time
	LastActivity time.Time
	ExpiresAt    time.Time
}

// AuthService handles authentication and session management.
type AuthService struct {
	store           storage.AdminUserStore
	jwtSecret       []byte
	tokenExpiration time.Duration
	sessions        map[string]*Session
	sessionMutex    sync.RWMutex
}

// NewAuthService creates a new authentication service.
func NewAuthService(store storage.AdminUserStore, jwtSecret string, tokenExpiration time.Duration) *AuthService {
	if tokenExpiration == 0 {
		tokenExpiration = DefaultTokenExpiration
	}

	return &AuthService{
		store:           store,
		jwtSecret:       []byte(jwtSecret),
		tokenExpiration: tokenExpiration,
		sessions:        make(map[string]*Session),
	}
}

// HashPassword hashes a password using bcrypt.
func HashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), BcryptCost)
	if err != nil {
		return "", fmt.Errorf("hash password: %w", err)
	}
	return string(hash), nil
}

// VerifyPassword verifies a password against a hash.
func VerifyPassword(password, hash string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
}

// Login authenticates a user and creates a new session.
func (s *AuthService) Login(ctx context.Context, username, password string) (*Session, string, error) {
	// Get user from storage
	user, err := s.store.Get(ctx, username)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, "", ErrInvalidCredentials
		}
		return nil, "", fmt.Errorf("get user: %w", err)
	}

	// Verify password
	if err := VerifyPassword(password, user.PasswordHash); err != nil {
		return nil, "", ErrInvalidCredentials
	}

	// Update last login time
	if err := s.store.UpdateLastLogin(ctx, username, time.Now()); err != nil {
		// Log error but don't fail login
		fmt.Printf("Failed to update last login: %v\n", err)
	}

	// Create session
	sessionID, err := generateSessionID()
	if err != nil {
		return nil, "", fmt.Errorf("generate session ID: %w", err)
	}

	now := time.Now()
	session := &Session{
		ID:           sessionID,
		UserID:       user.ID,
		Username:     user.Username,
		CreatedAt:    now,
		LastActivity: now,
		ExpiresAt:    now.Add(s.tokenExpiration),
	}

	// Store session
	s.sessionMutex.Lock()
	s.sessions[sessionID] = session
	s.sessionMutex.Unlock()

	// Generate JWT token
	token, err := s.GenerateToken(user.ID, user.Username)
	if err != nil {
		return nil, "", fmt.Errorf("generate token: %w", err)
	}

	return session, token, nil
}

// Logout removes a session.
func (s *AuthService) Logout(sessionID string) error {
	s.sessionMutex.Lock()
	defer s.sessionMutex.Unlock()

	if _, exists := s.sessions[sessionID]; !exists {
		return ErrSessionNotFound
	}

	delete(s.sessions, sessionID)
	return nil
}

// ValidateToken validates a JWT token and returns the claims.
func (s *AuthService) ValidateToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		// Validate signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return s.jwtSecret, nil
	})

	if err != nil {
		return nil, ErrInvalidToken
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, ErrInvalidToken
	}

	return claims, nil
}

// GenerateToken generates a new JWT token for a user.
func (s *AuthService) GenerateToken(userID, username string) (string, error) {
	now := time.Now()
	claims := &Claims{
		UserID:   userID,
		Username: username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(now.Add(s.tokenExpiration)),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err := token.SignedString(s.jwtSecret)
	if err != nil {
		return "", fmt.Errorf("sign token: %w", err)
	}

	return signedToken, nil
}

// GetSession retrieves a session by ID.
func (s *AuthService) GetSession(sessionID string) (*Session, error) {
	s.sessionMutex.RLock()
	defer s.sessionMutex.RUnlock()

	session, exists := s.sessions[sessionID]
	if !exists {
		return nil, ErrSessionNotFound
	}

	// Check if session is expired
	if time.Now().After(session.ExpiresAt) {
		return nil, ErrSessionExpired
	}

	return session, nil
}

// RefreshSession updates the last activity time for a session.
func (s *AuthService) RefreshSession(sessionID string) error {
	s.sessionMutex.Lock()
	defer s.sessionMutex.Unlock()

	session, exists := s.sessions[sessionID]
	if !exists {
		return ErrSessionNotFound
	}

	// Check if session is expired
	if time.Now().After(session.ExpiresAt) {
		delete(s.sessions, sessionID)
		return ErrSessionExpired
	}

	session.LastActivity = time.Now()
	return nil
}

// CleanupExpiredSessions removes expired sessions.
func (s *AuthService) CleanupExpiredSessions() int {
	s.sessionMutex.Lock()
	defer s.sessionMutex.Unlock()

	now := time.Now()
	count := 0

	for id, session := range s.sessions {
		if now.After(session.ExpiresAt) {
			delete(s.sessions, id)
			count++
		}
	}

	return count
}

// GetActiveSessions returns the number of active sessions.
func (s *AuthService) GetActiveSessions() int {
	s.sessionMutex.RLock()
	defer s.sessionMutex.RUnlock()
	return len(s.sessions)
}

// ChangePassword changes a user's password.
func (s *AuthService) ChangePassword(ctx context.Context, username, oldPassword, newPassword string) error {
	// Get user
	user, err := s.store.Get(ctx, username)
	if err != nil {
		return fmt.Errorf("get user: %w", err)
	}

	// Verify old password
	if err := VerifyPassword(oldPassword, user.PasswordHash); err != nil {
		return ErrInvalidCredentials
	}

	// Hash new password
	newHash, err := HashPassword(newPassword)
	if err != nil {
		return fmt.Errorf("hash new password: %w", err)
	}

	// Update user
	user.PasswordHash = newHash
	user.UpdatedAt = time.Now()

	if err := s.store.Upsert(ctx, *user); err != nil {
		return fmt.Errorf("update user: %w", err)
	}

	return nil
}

// generateSessionID generates a random session ID.
func generateSessionID() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// StartSessionCleanup starts a goroutine that periodically cleans up expired sessions.
func (s *AuthService) StartSessionCleanup(interval time.Duration) {
	if interval == 0 {
		interval = 15 * time.Minute
	}

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for range ticker.C {
			count := s.CleanupExpiredSessions()
			if count > 0 {
				fmt.Printf("Cleaned up %d expired admin sessions\n", count)
			}
		}
	}()
}
