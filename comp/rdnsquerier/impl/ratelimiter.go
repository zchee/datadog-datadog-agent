// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package rdnsquerierimpl

import (
	"context"

	"golang.org/x/time/rate"
)

type rateLimiter interface {
	allow() bool
	wait(context.Context) error
}

func newRateLimiter(config *rdnsQuerierConfig) rateLimiter {
	if !config.rateLimiterEnabled {
		return &rateLimiterNone{}
	}
	return &rateLimiterReal{
		limiter: rate.NewLimiter(rate.Limit(config.rateLimiterLimit), config.rateLimiterBurst),
	}
}

// Real rate limiter for when rdnsquerier rate limiting is enabled
type rateLimiterReal struct {
	limiter *rate.Limiter
}

func (r *rateLimiterReal) allow() bool {
	return r.limiter.Allow()
}

func (r *rateLimiterReal) wait(ctx context.Context) error {
	return r.limiter.Wait(ctx)
}

// No limit rate limiter for when rdnsquerier rate limiting is disabled
type rateLimiterNone struct{}

func (r *rateLimiterNone) allow() bool {
	return true
}

func (r *rateLimiterNone) wait(_ context.Context) error {
	return nil
}
