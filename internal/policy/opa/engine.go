package opa

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"github.com/rs/zerolog"
)

// Engine wraps OPA rego engine for policy evaluation
type Engine struct {
	policyDir string
	logger    zerolog.Logger

	// Compiled queries
	dnsQuery   rego.PreparedEvalQuery
	proxyQuery rego.PreparedEvalQuery

	// Policy modules
	modules map[string]*ast.Module
}

// NewEngine creates a new OPA engine
func NewEngine(policyDir string, logger zerolog.Logger) (*Engine, error) {
	e := &Engine{
		policyDir: policyDir,
		logger:    logger.With().Str("component", "opa").Logger(),
		modules:   make(map[string]*ast.Module),
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

	e.logger.Info().Str("policy_dir", policyDir).Msg("OPA engine initialized")

	return e, nil
}

// loadPolicies loads all .rego files from the policy directory
func (e *Engine) loadPolicies() error {
	// Find all .rego files
	files, err := filepath.Glob(filepath.Join(e.policyDir, "*.rego"))
	if err != nil {
		return fmt.Errorf("failed to glob policy files: %w", err)
	}

	if len(files) == 0 {
		return fmt.Errorf("no policy files found in %s", e.policyDir)
	}

	e.logger.Info().Int("count", len(files)).Msg("Loading policy files")

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

// prepareDNSQuery prepares the DNS action query
func (e *Engine) prepareDNSQuery() error {
	ctx := context.Background()

	// Build rego instance with all modules
	r := rego.New(
		rego.Query("data.kproxy.dns.action"),
		e.withModules()...,
	)

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

	// Build rego instance with all modules
	r := rego.New(
		rego.Query("data.kproxy.proxy.decision"),
		e.withModules()...,
	)

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
	for _, module := range e.modules {
		opts = append(opts, rego.Module(module.Package.Path.String(), module.String()))
	}
	return opts
}

// EvaluateDNS evaluates DNS action for a query
func (e *Engine) EvaluateDNS(ctx context.Context, input map[string]interface{}) (string, error) {
	startTime := time.Now()

	// Evaluate the query
	results, err := e.dnsQuery.Eval(ctx, rego.EvalInput(input))
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
	Action              string `json:"action"`
	Reason              string `json:"reason"`
	BlockPage           string `json:"block_page"`
	MatchedRuleID       string `json:"matched_rule_id"`
	Category            string `json:"category"`
	InjectTimer         bool   `json:"inject_timer"`
	TimeRemainingMinutes int    `json:"time_remaining_minutes"`
	UsageLimitID        string `json:"usage_limit_id"`
}

// EvaluateProxy evaluates a proxy request
func (e *Engine) EvaluateProxy(ctx context.Context, input map[string]interface{}) (*ProxyDecision, error) {
	startTime := time.Now()

	// Evaluate the query
	results, err := e.proxyQuery.Eval(ctx, rego.EvalInput(input))
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

// Reload reloads all policies from disk
func (e *Engine) Reload() error {
	e.logger.Info().Msg("Reloading OPA policies")

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
