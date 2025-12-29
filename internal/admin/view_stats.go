package admin

import (
	"net/http"
	"sort"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/goodtune/kproxy/internal/storage"
	"github.com/rs/zerolog"
)

// StatsViews handles statistics-related API requests.
// Note: Device/profile/rule stats removed - config now in OPA policies
type StatsViews struct {
	logStore   storage.LogStore
	usageStore storage.UsageStore
	logger     zerolog.Logger
}

// NewStatsViews creates a new statistics views instance.
func NewStatsViews(
	logStore storage.LogStore,
	usageStore storage.UsageStore,
	logger zerolog.Logger,
) *StatsViews {
	return &StatsViews{
		logStore:   logStore,
		usageStore: usageStore,
		logger:     logger.With().Str("handler", "stats").Logger(),
	}
}

// DashboardStats represents the statistics for the dashboard.
// Note: Device/profile/rule counts removed - config now in OPA policies
type DashboardStats struct {
	RequestsToday  int         `json:"requests_today"`
	ActiveSessions int         `json:"active_sessions"`
	BlockedToday   int         `json:"blocked_today"`
	RecentBlocks   []BlockInfo `json:"recent_blocks"`
	TopBlockedDomains []DomainCount   `json:"top_blocked_domains"`
	RequestTimeline   []TimelinePoint `json:"request_timeline"`
}

// BlockInfo represents a blocked request.
type BlockInfo struct {
	Timestamp time.Time `json:"timestamp"`
	Device    string    `json:"device"`
	Domain    string    `json:"domain"`
	Reason    string    `json:"reason"`
}

// DomainCount represents a domain with its count.
type DomainCount struct {
	Domain string `json:"domain"`
	Count  int    `json:"count"`
}

// TimelinePoint represents a point in the request timeline.
type TimelinePoint struct {
	Time  string `json:"time"`
	Count int    `json:"count"`
}

// GetDashboardStats returns comprehensive dashboard statistics.
func (v *StatsViews) GetDashboardStats(ctx *gin.Context) {
	stats := DashboardStats{
		RecentBlocks:      []BlockInfo{},
		TopBlockedDomains: []DomainCount{},
		RequestTimeline:   []TimelinePoint{},
	}

	// Note: Device/profile/rule counts removed - config now in OPA policies

	// Get today's start time
	now := time.Now()
	todayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())

	// Get active sessions
	sessions, err := v.usageStore.ListActiveSessions(ctx.Request.Context())
	if err != nil {
		v.logger.Error().Err(err).Msg("Failed to get active sessions")
	} else {
		stats.ActiveSessions = len(sessions)
	}

	// Query request logs for today
	requestFilter := storage.RequestLogFilter{
		StartTime: &todayStart,
		Limit:     10000, // Get all today's requests
	}
	requestLogs, err := v.logStore.QueryRequestLogs(ctx.Request.Context(), requestFilter)
	if err != nil {
		v.logger.Error().Err(err).Msg("Failed to query request logs")
	} else {
		stats.RequestsToday = len(requestLogs)

		// Count blocked requests
		blockedCount := 0
		var recentBlocks []BlockInfo
		blockedDomains := make(map[string]int)

		for _, log := range requestLogs {
			if log.Action == storage.ActionBlock {
				blockedCount++
				blockedDomains[log.Host]++

				// Collect recent blocks (last 10)
				if len(recentBlocks) < 10 {
					deviceName := log.DeviceID
					if deviceName == "" {
						deviceName = "Unknown"
					}

					reason := "Policy"
					if log.Reason != "" {
						reason = log.Reason
					}

					recentBlocks = append(recentBlocks, BlockInfo{
						Timestamp: log.Timestamp,
						Device:    deviceName,
						Domain:    log.Host,
						Reason:    reason,
					})
				}
			}
		}

		stats.BlockedToday = blockedCount
		stats.RecentBlocks = recentBlocks

		// Get top blocked domains
		type domainCountPair struct {
			domain string
			count  int
		}
		var domainPairs []domainCountPair
		for domain, count := range blockedDomains {
			domainPairs = append(domainPairs, domainCountPair{domain, count})
		}
		sort.Slice(domainPairs, func(i, j int) bool {
			return domainPairs[i].count > domainPairs[j].count
		})

		// Take top 10
		limit := 10
		if len(domainPairs) < limit {
			limit = len(domainPairs)
		}
		for i := 0; i < limit; i++ {
			stats.TopBlockedDomains = append(stats.TopBlockedDomains, DomainCount{
				Domain: domainPairs[i].domain,
				Count:  domainPairs[i].count,
			})
		}

		// Build timeline (hourly for today)
		hourCounts := make(map[int]int)
		for _, log := range requestLogs {
			hour := log.Timestamp.Hour()
			hourCounts[hour]++
		}

		// Create timeline points for all 24 hours
		for hour := 0; hour < 24; hour++ {
			timeStr := time.Date(now.Year(), now.Month(), now.Day(), hour, 0, 0, 0, now.Location()).
				Format("15:04")
			stats.RequestTimeline = append(stats.RequestTimeline, TimelinePoint{
				Time:  timeStr,
				Count: hourCounts[hour],
			})
		}
	}

	ctx.JSON(http.StatusOK, stats)
}

// GetDeviceStats returns per-device statistics.
// Note: Device stats removed - device config now in OPA policies
func (v *StatsViews) GetDeviceStats(ctx *gin.Context) {
	// Return empty stats - device config is now in OPA policies
	ctx.JSON(http.StatusOK, gin.H{
		"message": "Device stats unavailable - device configuration moved to OPA policies",
		"devices": []interface{}{},
	})
	return

	/* Removed device query code
	devices, err := v.deviceStore.List(ctx.Request.Context())
	if err != nil {
		v.logger.Error().Err(err).Msg("Failed to list devices")
		ctx.JSON(http.StatusInternalServerError, gin.H{
			"error":   "server_error",
			"message": "Failed to retrieve device stats",
		})
		return
	}

	now := time.Now()
	todayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())

	type DeviceStats struct {
		DeviceID      string `json:"device_id"`
		DeviceName    string `json:"device_name"`
		RequestsToday int    `json:"requests_today"`
		BlockedToday  int    `json:"blocked_today"`
	}

	var stats []DeviceStats

	for _, device := range devices {
		deviceStats := DeviceStats{
			DeviceID:   device.ID,
			DeviceName: device.Name,
		}

		// Query logs for this device
		filter := storage.RequestLogFilter{
			DeviceID:  device.ID,
			StartTime: &todayStart,
			Limit:     10000,
		}

		logs, err := v.logStore.QueryRequestLogs(ctx.Request.Context(), filter)
		if err != nil {
			v.logger.Error().Err(err).Str("deviceID", device.ID).Msg("Failed to query device logs")
			continue
		}

		deviceStats.RequestsToday = len(logs)
		for _, log := range logs {
			if log.Action == storage.ActionBlock {
				deviceStats.BlockedToday++
			}
		}

		stats = append(stats, deviceStats)
	}

	ctx.JSON(http.StatusOK, gin.H{
		"device_stats": stats,
		"count":        len(stats),
	})
	*/
}

// GetTopDomains returns the most accessed domains.
func (v *StatsViews) GetTopDomains(ctx *gin.Context) {
	now := time.Now()
	todayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())

	filter := storage.RequestLogFilter{
		StartTime: &todayStart,
		Limit:     10000,
	}

	logs, err := v.logStore.QueryRequestLogs(ctx.Request.Context(), filter)
	if err != nil {
		v.logger.Error().Err(err).Msg("Failed to query request logs")
		ctx.JSON(http.StatusInternalServerError, gin.H{
			"error":   "server_error",
			"message": "Failed to retrieve top domains",
		})
		return
	}

	domainCounts := make(map[string]int)
	for _, log := range logs {
		domainCounts[log.Host]++
	}

	type domainPair struct {
		domain string
		count  int
	}
	var pairs []domainPair
	for domain, count := range domainCounts {
		pairs = append(pairs, domainPair{domain, count})
	}

	sort.Slice(pairs, func(i, j int) bool {
		return pairs[i].count > pairs[j].count
	})

	// Take top 20
	limit := 20
	if len(pairs) < limit {
		limit = len(pairs)
	}

	var topDomains []DomainCount
	for i := 0; i < limit; i++ {
		topDomains = append(topDomains, DomainCount{
			Domain: pairs[i].domain,
			Count:  pairs[i].count,
		})
	}

	ctx.JSON(http.StatusOK, gin.H{
		"top_domains": topDomains,
		"count":       len(topDomains),
	})
}

// GetBlockedStats returns statistics about blocked requests.
func (v *StatsViews) GetBlockedStats(ctx *gin.Context) {
	now := time.Now()
	todayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())

	filter := storage.RequestLogFilter{
		Action:    storage.ActionBlock,
		StartTime: &todayStart,
		Limit:     10000,
	}

	logs, err := v.logStore.QueryRequestLogs(ctx.Request.Context(), filter)
	if err != nil {
		v.logger.Error().Err(err).Msg("Failed to query blocked requests")
		ctx.JSON(http.StatusInternalServerError, gin.H{
			"error":   "server_error",
			"message": "Failed to retrieve blocked stats",
		})
		return
	}

	reasonCounts := make(map[string]int)
	for _, log := range logs {
		reason := log.Reason
		if reason == "" {
			reason = "Policy"
		}
		reasonCounts[reason]++
	}

	type ReasonCount struct {
		Reason string `json:"reason"`
		Count  int    `json:"count"`
	}

	var reasons []ReasonCount
	for reason, count := range reasonCounts {
		reasons = append(reasons, ReasonCount{
			Reason: reason,
			Count:  count,
		})
	}

	sort.Slice(reasons, func(i, j int) bool {
		return reasons[i].Count > reasons[j].Count
	})

	ctx.JSON(http.StatusOK, gin.H{
		"blocked_reasons": reasons,
		"total_blocked":   len(logs),
	})
}
