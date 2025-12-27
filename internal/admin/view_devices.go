package admin

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/goodtune/kproxy/internal/storage"
	"github.com/rs/zerolog"
)

// DeviceViews handles device-related API requests.
type DeviceViews struct {
	store  storage.DeviceStore
	logger zerolog.Logger
}

// NewDeviceViews creates a new device views instance.
func NewDeviceViews(store storage.DeviceStore, logger zerolog.Logger) *DeviceViews {
	return &DeviceViews{
		store:  store,
		logger: logger.With().Str("handler", "device").Logger(),
	}
}

// List returns all devices.
func (v *DeviceViews) List(ctx *gin.Context) {
	devices, err := v.store.List(ctx.Request.Context())
	if err != nil {
		v.logger.Error().Err(err).Msg("Failed to list devices")
		ctx.JSON(http.StatusInternalServerError, gin.H{
			"error":   "server_error",
			"message": "Failed to retrieve devices",
		})
		return
	}

	ctx.JSON(http.StatusOK, gin.H{
		"devices": devices,
		"count":   len(devices),
	})
}

// Get returns a single device by ID.
func (v *DeviceViews) Get(ctx *gin.Context) {
	id := ctx.Param("id")

	device, err := v.store.Get(ctx.Request.Context(), id)
	if err != nil {
		if err == storage.ErrNotFound {
			ctx.JSON(http.StatusNotFound, gin.H{
				"error":   "not_found",
				"message": "Device not found",
			})
			return
		}
		v.logger.Error().Err(err).Str("id", id).Msg("Failed to get device")
		ctx.JSON(http.StatusInternalServerError, gin.H{
			"error":   "server_error",
			"message": "Failed to retrieve device",
		})
		return
	}

	ctx.JSON(http.StatusOK, device)
}

// Create creates a new device.
func (v *DeviceViews) Create(ctx *gin.Context) {
	var device storage.Device
	if err := ctx.ShouldBindJSON(&device); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error":   "bad_request",
			"message": "Invalid request body",
		})
		return
	}

	// Validate device
	if device.Name == "" {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error":   "bad_request",
			"message": "Device name is required",
		})
		return
	}

	if len(device.Identifiers) == 0 {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error":   "bad_request",
			"message": "At least one identifier is required",
		})
		return
	}

	// Generate ID if not provided
	if device.ID == "" {
		device.ID = generateID("dev")
	}

	// Set timestamps
	now := time.Now()
	device.CreatedAt = now
	device.UpdatedAt = now

	// Set default active state
	if !device.Active {
		device.Active = true
	}

	if err := v.store.Upsert(ctx.Request.Context(), device); err != nil {
		v.logger.Error().Err(err).Msg("Failed to create device")
		ctx.JSON(http.StatusInternalServerError, gin.H{
			"error":   "server_error",
			"message": "Failed to create device",
		})
		return
	}

	v.logger.Info().Str("id", device.ID).Str("name", device.Name).Msg("Device created")
	ctx.JSON(http.StatusCreated, device)
}

// Update updates an existing device.
func (v *DeviceViews) Update(ctx *gin.Context) {
	id := ctx.Param("id")

	// Get existing device
	existing, err := v.store.Get(ctx.Request.Context(), id)
	if err != nil {
		if err == storage.ErrNotFound {
			ctx.JSON(http.StatusNotFound, gin.H{
				"error":   "not_found",
				"message": "Device not found",
			})
			return
		}
		v.logger.Error().Err(err).Str("id", id).Msg("Failed to get device")
		ctx.JSON(http.StatusInternalServerError, gin.H{
			"error":   "server_error",
			"message": "Failed to retrieve device",
		})
		return
	}

	var updates storage.Device
	if err := ctx.ShouldBindJSON(&updates); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error":   "bad_request",
			"message": "Invalid request body",
		})
		return
	}

	// Preserve ID and creation time
	updates.ID = existing.ID
	updates.CreatedAt = existing.CreatedAt
	updates.UpdatedAt = time.Now()

	// Validate updates
	if updates.Name == "" {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error":   "bad_request",
			"message": "Device name is required",
		})
		return
	}

	if len(updates.Identifiers) == 0 {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error":   "bad_request",
			"message": "At least one identifier is required",
		})
		return
	}

	if err := v.store.Upsert(ctx.Request.Context(), updates); err != nil {
		v.logger.Error().Err(err).Str("id", id).Msg("Failed to update device")
		ctx.JSON(http.StatusInternalServerError, gin.H{
			"error":   "server_error",
			"message": "Failed to update device",
		})
		return
	}

	v.logger.Info().Str("id", id).Str("name", updates.Name).Msg("Device updated")
	ctx.JSON(http.StatusOK, updates)
}

// Delete deletes a device.
func (v *DeviceViews) Delete(ctx *gin.Context) {
	id := ctx.Param("id")

	if err := v.store.Delete(ctx.Request.Context(), id); err != nil {
		if err == storage.ErrNotFound {
			ctx.JSON(http.StatusNotFound, gin.H{
				"error":   "not_found",
				"message": "Device not found",
			})
			return
		}
		v.logger.Error().Err(err).Str("id", id).Msg("Failed to delete device")
		ctx.JSON(http.StatusInternalServerError, gin.H{
			"error":   "server_error",
			"message": "Failed to delete device",
		})
		return
	}

	v.logger.Info().Str("id", id).Msg("Device deleted")
	ctx.JSON(http.StatusOK, gin.H{
		"message": "Device deleted successfully",
	})
}

// generateID generates a unique ID with a prefix.
func generateID(prefix string) string {
	return prefix + "-" + time.Now().Format("20060102150405")
}
