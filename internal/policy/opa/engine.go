package opa

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/rs/zerolog"
)

// Config holds OPA engine configuration
type Config struct {
	Source      string        // "filesystem" or "remote"
	PolicyDir   string        // Directory for filesystem source
	PolicyURLs  []string      // URLs for remote source
	HTTPTimeout time.Duration // Timeout for HTTP requests
	HTTPRetries int           // Number of retries for failed requests
}

// Engine wraps OPA rego engine for policy evaluation
type Engine struct {
	config Config
	logger zerolog.Logger

	// Compiled queries (protected by mu)
	mu         sync.RWMutex
	dnsQuery   rego.PreparedEvalQuery
	proxyQuery rego.PreparedEvalQuery

	// Policy modules (protected by mu)
	modules map[string]*ast.Module

	// HTTP client for remote loading
	httpClient *http.Client
}

// NewEngine creates a new OPA engine
func NewEngine(config Config, logger zerolog.Logger) (*Engine, error) {
	e := &Engine{
		config:  config,
		logger:  logger.With().Str("component", "opa").Logger(),
		modules: make(map[string]*ast.Module),
		httpClient: &http.Client{
			Timeout: config.HTTPTimeout,
		},
	}

	// Validate configuration
	if err := e.validateConfig(); err != nil {
		return nil, fmt.Errorf("invalid OPA configuration: %w", err)
	}

	// Load and compile policies
	if err := e.loadPolicies(); err != nil {
		return nil, fmt.Errorf("failed to load policies: %w", err)
	}

	// Prepare DNS query
	if err := e.prepareDNSQuery(); err != nil {
		return nil, fmt.Errorf("failed to prepare DNS query: %w", err)
	}

	// Prepare Proxy query
	if err := e.prepareProxyQuery(); err != nil {
		return nil, fmt.Errorf("failed to prepare proxy query: %w", err)
	}

	e.logger.Info().
		Str("source", config.Source).
		Str("policy_dir", config.PolicyDir).
		Int("policy_urls", len(config.PolicyURLs)).
		Msg("OPA engine initialized")

	return e, nil
}

// validateConfig validates the engine configuration
func (e *Engine) validateConfig() error {
	switch strings.ToLower(e.config.Source) {
	case "filesystem":
		if e.config.PolicyDir == "" {
			return fmt.Errorf("policy_dir is required for filesystem source")
		}
	case "remote":
		if len(e.config.PolicyURLs) == 0 {
			return fmt.Errorf("policy_urls is required for remote source")
		}
		for _, url := range e.config.PolicyURLs {
			if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
				return fmt.Errorf("invalid policy URL (must be http:// or https://): %s", url)
			}
		}
	default:
		return fmt.Errorf("invalid policy source: %s (must be 'filesystem' or 'remote')", e.config.Source)
	}
	return nil
}

// loadPolicies loads policies based on configured source
func (e *Engine) loadPolicies() error {
	switch strings.ToLower(e.config.Source) {
	case "filesystem":
		return e.loadPoliciesFromFilesystem()
	case "remote":
		return e.loadPoliciesFromRemote()
	default:
		return fmt.Errorf("unknown policy source: %s", e.config.Source)
	}
}

// loadPoliciesFromFilesystem loads all .rego files from the policy directory
func (e *Engine) loadPoliciesFromFilesystem() error {
	// Find all .rego files
	files, err := filepath.Glob(filepath.Join(e.config.PolicyDir, "*.rego"))
	if err != nil {
		return fmt.Errorf("failed to glob policy files: %w", err)
	}

	if len(files) == 0 {
		return fmt.Errorf("no policy files found in %s", e.config.PolicyDir)
	}

	e.logger.Info().Int("count", len(files)).Str("dir", e.config.PolicyDir).Msg("Loading policy files from filesystem")

	for _, file := range files {
		content, err := os.ReadFile(file)
		if err != nil {
			return fmt.Errorf("failed to read policy file %s: %w", file, err)
		}

		// Parse the module
		module, err := ast.ParseModule(file, string(content))
		if err != nil {
			return fmt.Errorf("failed to parse policy file %s: %w", file, err)
		}

		e.modules[file] = module
		e.logger.Debug().Str("file", file).Str("package", module.Package.Path.String()).Msg("Loaded policy module")
	}

	return nil
}

// loadPoliciesFromRemote loads policy files from remote HTTP/HTTPS URLs
func (e *Engine) loadPoliciesFromRemote() error {
	e.logger.Info().Int("count", len(e.config.PolicyURLs)).Msg("Loading policy files from remote URLs")

	for _, url := range e.config.PolicyURLs {
		content, err := e.fetchPolicyWithRetry(url)
		if err != nil {
			return fmt.Errorf("failed to fetch policy from %s: %w", url, err)
		}

		// Parse the module (use URL as identifier)
		module, err := ast.ParseModule(url, string(content))
		if err != nil {
			return fmt.Errorf("failed to parse policy from %s: %w", url, err)
		}

		e.modules[url] = module
		e.logger.Debug().Str("url", url).Str("package", module.Package.Path.String()).Msg("Loaded policy module from remote")
	}

	return nil
}

// fetchPolicyWithRetry fetches a policy from URL with exponential backoff retry
func (e *Engine) fetchPolicyWithRetry(url string) ([]byte, error) {
	var lastErr error
	maxRetries := e.config.HTTPRetries
	if maxRetries <= 0 {
		maxRetries = 1 // At least try once
	}

	for attempt := 0; attempt < maxRetries; attempt++ {
		if attempt > 0 {
			// Exponential backoff: 2s, 4s, 8s, 16s
			backoff := time.Duration(1<<uint(attempt)) * 2 * time.Second
			e.logger.Warn().
				Str("url", url).
				Int("attempt", attempt+1).
				Int("max_attempts", maxRetries).
				Dur("backoff", backoff).
				Msg("Retrying policy fetch after failure")
			time.Sleep(backoff)
		}

		content, err := e.fetchPolicy(url)
		if err == nil {
			if attempt > 0 {
				e.logger.Info().
					Str("url", url).
					Int("attempts", attempt+1).
					Msg("Successfully fetched policy after retry")
			}
			return content, nil
		}

		lastErr = err
		e.logger.Warn().
			Err(err).
			Str("url", url).
			Int("attempt", attempt+1).
			Int("max_attempts", maxRetries).
			Msg("Failed to fetch policy")
	}

	return nil, fmt.Errorf("failed after %d attempts: %w", maxRetries, lastErr)
}

// fetchPolicy fetches a policy file from a remote URL
func (e *Engine) fetchPolicy(url string) ([]byte, error) {
	e.logger.Debug().Str("url", url).Msg("Fetching policy from remote")

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := e.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			e.logger.Warn().Err(closeErr).Msg("Failed to close response body")
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, resp.Status)
	}

	// Read response body (limit to 10MB to prevent memory issues)
	const maxPolicySize = 10 * 1024 * 1024
	limitedReader := io.LimitReader(resp.Body, maxPolicySize)
	content, err := io.ReadAll(limitedReader)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if len(content) == maxPolicySize {
		return nil, fmt.Errorf("policy exceeds maximum size of %d bytes", maxPolicySize)
	}

	e.logger.Debug().
		Str("url", url).
		Int("size_bytes", len(content)).
		Msg("Successfully fetched policy")

	return content, nil
}

// prepareDNSQuery prepares the DNS action query
func (e *Engine) prepareDNSQuery() error {
	ctx := context.Background()

	// Build rego options: query + modules
	opts := []func(*rego.Rego){rego.Query("data.kproxy.dns.action")}
	opts = append(opts, e.withModules()...)

	// Build rego instance with all options
	r := rego.New(opts...)

	// Prepare the query
	query, err := r.PrepareForEval(ctx)
	if err != nil {
		return fmt.Errorf("failed to prepare DNS query: %w", err)
	}

	e.dnsQuery = query
	e.logger.Debug().Msg("DNS query prepared")

	return nil
}

// prepareProxyQuery prepares the proxy decision query
func (e *Engine) prepareProxyQuery() error {
	ctx := context.Background()

	// Build rego options: query + modules
	opts := []func(*rego.Rego){rego.Query("data.kproxy.proxy.decision")}
	opts = append(opts, e.withModules()...)

	// Build rego instance with all options
	r := rego.New(opts...)

	// Prepare the query
	query, err := r.PrepareForEval(ctx)
	if err != nil {
		return fmt.Errorf("failed to prepare proxy query: %w", err)
	}

	e.proxyQuery = query
	e.logger.Debug().Msg("Proxy query prepared")

	return nil
}

// withModules returns rego options for all loaded modules
func (e *Engine) withModules() []func(*rego.Rego) {
	opts := make([]func(*rego.Rego), 0, len(e.modules))
	for name, module := range e.modules {
		opts = append(opts, rego.Module(name, module.String()))
	}
	return opts
}

// EvaluateDNS evaluates DNS action for a query
func (e *Engine) EvaluateDNS(ctx context.Context, input map[string]interface{}) (string, error) {
	startTime := time.Now()

	// Acquire read lock to safely access prepared query
	e.mu.RLock()
	dnsQuery := e.dnsQuery
	e.mu.RUnlock()

	// Evaluate the query
	results, err := dnsQuery.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		return "", fmt.Errorf("DNS query evaluation failed: %w", err)
	}

	duration := time.Since(startTime)
	e.logger.Debug().Dur("duration_ms", duration).Msg("DNS query evaluated")

	// Extract result
	if len(results) == 0 {
		return "", fmt.Errorf("no results from DNS query")
	}

	if len(results[0].Expressions) == 0 {
		return "", fmt.Errorf("no expressions in DNS query result")
	}

	action, ok := results[0].Expressions[0].Value.(string)
	if !ok {
		return "", fmt.Errorf("DNS action is not a string: %T", results[0].Expressions[0].Value)
	}

	return action, nil
}

// ProxyDecision represents a proxy policy decision
type ProxyDecision struct {
	Action               string `json:"action"`
	Reason               string `json:"reason"`
	BlockPage            string `json:"block_page"`
	MatchedRuleID        string `json:"matched_rule_id"`
	Category             string `json:"category"`
	InjectTimer          bool   `json:"inject_timer"`
	TimeRemainingMinutes int    `json:"time_remaining_minutes"`
	UsageLimitID         string `json:"usage_limit_id"`
}

// EvaluateProxy evaluates a proxy request
func (e *Engine) EvaluateProxy(ctx context.Context, input map[string]interface{}) (*ProxyDecision, error) {
	startTime := time.Now()

	// Acquire read lock to safely access prepared query
	e.mu.RLock()
	proxyQuery := e.proxyQuery
	e.mu.RUnlock()

	// Evaluate the query
	results, err := proxyQuery.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		return nil, fmt.Errorf("proxy query evaluation failed: %w", err)
	}

	duration := time.Since(startTime)
	e.logger.Debug().Dur("duration_ms", duration).Msg("Proxy query evaluated")

	// Extract result
	if len(results) == 0 {
		return nil, fmt.Errorf("no results from proxy query")
	}

	if len(results[0].Expressions) == 0 {
		return nil, fmt.Errorf("no expressions in proxy query result")
	}

	// Convert result to ProxyDecision
	resultBytes, err := json.Marshal(results[0].Expressions[0].Value)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal proxy decision: %w", err)
	}

	var decision ProxyDecision
	if err := json.Unmarshal(resultBytes, &decision); err != nil {
		return nil, fmt.Errorf("failed to unmarshal proxy decision: %w", err)
	}

	return &decision, nil
}

// Reload reloads all policies
func (e *Engine) Reload() error {
	e.logger.Info().Msg("Reloading OPA policies")

	// Acquire write lock to safely modify engine state
	e.mu.Lock()
	defer e.mu.Unlock()

	// Clear existing modules
	e.modules = make(map[string]*ast.Module)

	// Reload policies
	if err := e.loadPolicies(); err != nil {
		return fmt.Errorf("failed to reload policies: %w", err)
	}

	// Re-prepare queries
	if err := e.prepareDNSQuery(); err != nil {
		return fmt.Errorf("failed to re-prepare DNS query: %w", err)
	}

	if err := e.prepareProxyQuery(); err != nil {
		return fmt.Errorf("failed to re-prepare proxy query: %w", err)
	}

	e.logger.Info().Msg("OPA policies reloaded successfully")

	return nil
}
