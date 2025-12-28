package policy

import "time"

// Clock provides time information for policy evaluation.
// This interface allows time to be mocked in tests.
type Clock interface {
	Now() time.Time
}

// RealClock provides actual system time.
type RealClock struct{}

// Now returns the current system time.
func (RealClock) Now() time.Time {
	return time.Now()
}

// TestClock provides fixed time for testing.
type TestClock struct {
	CurrentTime time.Time
}

// Now returns the test time.
func (t *TestClock) Now() time.Time {
	return t.CurrentTime
}
