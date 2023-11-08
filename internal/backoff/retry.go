package backoff

import (
	"errors"
	"fmt"
	"log/slog"
	"math"
	"math/rand"
	"time"
)

var ErrMaxRetriesReached = errors.New("operation failed after reaching the maximum number of retries")

// RetryConfig holds the configuration parameters for the retry mechanism.
type RetryConfig struct {
	MaxRetries   int
	InitialDelay time.Duration
	MaxDelay     time.Duration
	JitterFactor float64
}

// DefaultRetryConfig provides a default configuration for retries.
var DefaultRetryConfig = RetryConfig{
	MaxRetries:   5,
	InitialDelay: 1 * time.Second,
	MaxDelay:     32 * time.Second,
	JitterFactor: 0.6,
}

// retryWithBackoff retries the given operation using an exponential backoff mechanism.
// It uses the provided RetryConfig for configuration. If the operation continues to fail
// after the maximum number of retries, the last error is returned.
//
// The delay between retries is subject to jitter (randomness)
//
// Example:
//
//	op := &SomeOperation{}
//	err := retryWithBackoff(op, DefaultRetryConfig)
//	if err != nil {
//	    log.Fatalf("Operation failed after retries: %v", err)
//	}
func RetryWithBackoff(op func() error, config RetryConfig) error {
	delay := config.InitialDelay

	for i := 0; i < config.MaxRetries; i++ {
		err := op()
		if err == nil {
			return nil
		}

		// Calculate the next delay with jitter
		jitter := time.Duration(rand.Float64() * config.JitterFactor * float64(delay))
		nextDelay := delay + jitter
		slog.Info(fmt.Sprintf("Attempt %d failed; retrying in %v...\n", i+1, nextDelay))
		time.Sleep(nextDelay)

		// Double the delay for the next iteration, but don't exceed MaxDelay
		delay = time.Duration(math.Min(float64(2*delay), float64(config.MaxDelay)))
	}

	return ErrMaxRetriesReached
}
