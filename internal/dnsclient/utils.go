package dnsclient

import (
	"context"
	"fmt"
	"log/slog"
	"os/exec"
	"time"
)

const (
	maxRetries    = 3
	retryInterval = 5 * time.Second
	cmdTimeout    = 10 * time.Second
	sleepDuration = 5 * time.Second
)

func (c *BindClient) syncJournalToZoneFile() error {
	for retries := 0; retries < maxRetries; retries++ {
		slog.Debug("Attempting rndc sync", "attempt", retries+1)
		if err := runCmdWithTimeout("rndc", "sync", c.zone); err != nil {
			slog.Warn("rndc sync command failed", "error", err.Error())
			time.Sleep(retryInterval)
			continue
		}
		time.Sleep(sleepDuration)
		return nil
	}
	return fmt.Errorf("Failed to sync journal to zone file after %d retries", maxRetries)
}

func runCmdWithTimeout(command string, args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), cmdTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, command, args...)

	if err := cmd.Run(); err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return fmt.Errorf("command timed out")
		}
		return err
	}
	return nil
}
