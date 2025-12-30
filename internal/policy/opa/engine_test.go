package opa

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/rs/zerolog"
)

// TestReloadThreadSafety tests that reload is thread-safe with concurrent evaluations
func TestReloadThreadSafety(t *testing.T) {
	// Create a test OPA engine with filesystem policies
	config := Config{
		Source:    "filesystem",
		PolicyDir: "../../../policies",
	}

	logger := zerolog.Nop() // Silent logger for tests
	engine, err := NewEngine(config, logger)
	if err != nil {
		t.Skipf("Skipping thread safety test - policies not available: %v", err)
		return
	}

	// Run concurrent operations
	var wg sync.WaitGroup
	ctx := context.Background()
	done := make(chan bool)

	// Start goroutines that continuously evaluate policies
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-done:
					return
				default:
					// Evaluate DNS query
					input := map[string]interface{}{
						"client_ip":  "192.168.1.100",
						"client_mac": "aa:bb:cc:dd:ee:ff",
						"domain":     "example.com",
					}
					_, _ = engine.EvaluateDNS(ctx, input)

					// Small delay to avoid spinning too fast
					time.Sleep(1 * time.Millisecond)
				}
			}
		}()
	}

	// Start goroutines that continuously evaluate proxy requests
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-done:
					return
				default:
					// Evaluate proxy request
					input := map[string]interface{}{
						"client_ip":  "192.168.1.100",
						"client_mac": "aa:bb:cc:dd:ee:ff",
						"host":       "example.com",
						"path":       "/",
						"method":     "GET",
						"time": map[string]interface{}{
							"day_of_week": 1,
							"hour":        14,
							"minute":      30,
						},
						"usage": map[string]interface{}{},
					}
					_, _ = engine.EvaluateProxy(ctx, input)

					// Small delay to avoid spinning too fast
					time.Sleep(1 * time.Millisecond)
				}
			}
		}()
	}

	// Perform multiple reloads while evaluations are happening
	for i := 0; i < 5; i++ {
		time.Sleep(10 * time.Millisecond)
		if err := engine.Reload(); err != nil {
			t.Errorf("Reload failed: %v", err)
		}
	}

	// Signal all goroutines to stop
	close(done)
	wg.Wait()

	// If we get here without data races or panics, the test passed
	t.Log("Thread safety test completed successfully")
}

// TestReloadWithoutPolicies tests reload behavior when policies are not available
func TestReloadWithoutPolicies(t *testing.T) {
	config := Config{
		Source:    "filesystem",
		PolicyDir: "/nonexistent/path",
	}

	logger := zerolog.Nop()

	// NewEngine should fail with invalid path
	_, err := NewEngine(config, logger)
	if err == nil {
		t.Error("Expected error when creating engine with invalid policy dir")
	}
}
