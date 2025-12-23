package admin

import (
	"context"
	"errors"
	"time"

	"github.com/goodtune/kproxy/internal/storage"
	"github.com/rs/zerolog"
)

// EnsureInitialAdminUser creates the initial admin user if no users exist.
func EnsureInitialAdminUser(ctx context.Context, store storage.AdminUserStore, username, password string, logger zerolog.Logger) error {
	// Check if any users exist
	users, err := store.List(ctx)
	if err != nil {
		return err
	}

	if len(users) > 0 {
		logger.Info().Int("count", len(users)).Msg("Admin users already exist")
		return nil
	}

	// No users exist, create initial admin user
	if username == "" {
		username = "admin"
	}

	if password == "" {
		return errors.New("initial admin password cannot be empty")
	}

	// Hash password
	passwordHash, err := HashPassword(password)
	if err != nil {
		return err
	}

	// Create user
	user := storage.AdminUser{
		ID:           "admin-1",
		Username:     username,
		PasswordHash: passwordHash,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	if err := store.Upsert(ctx, user); err != nil {
		return err
	}

	logger.Info().
		Str("username", username).
		Msg("Created initial admin user")

	// Warn if using default password
	if password == "admin" || password == "password" {
		logger.Warn().
			Msg("⚠️  WARNING: Using default admin password! Please change it immediately for security.")
	}

	return nil
}
