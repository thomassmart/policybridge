package api

import (
	"context"
	"fmt"
	"time"

	"github.com/policybridge/policybridge/internal/session"
)

// runWithHeartbeat runs fn in a goroutine and updates job progress while waiting.
// Progress moves from startPct toward endPct-1 based on elapsed time.
func runWithHeartbeat(ctx context.Context, job *session.Job, startPct, endPct int, label string, fn func() error) error {
	done := make(chan error, 1)
	go func() { done <- fn() }()

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	start := time.Now()

	for {
		select {
		case err := <-done:
			return err
		case <-ctx.Done():
			return context.Canceled
		case <-ticker.C:
			elapsed := int(time.Since(start).Seconds())
			span := endPct - startPct
			if span < 1 {
				span = 1
			}
			bump := elapsed / 15
			if bump > span-1 {
				bump = span - 1
			}
			job.SetProgress(startPct+bump, fmt.Sprintf("%s… %ds elapsed (still running)", label, elapsed))
		}
	}
}
