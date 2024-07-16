// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

// Package rdnsquerierimpl implements the rdnsquerier component interface
package rdnsquerierimpl

import (
	"context"
	"fmt"
	"net/netip"

	"github.com/DataDog/datadog-agent/comp/core/config"
	"github.com/DataDog/datadog-agent/comp/core/log"
	"github.com/DataDog/datadog-agent/comp/core/telemetry"
	compdef "github.com/DataDog/datadog-agent/comp/def"
	rdnsquerier "github.com/DataDog/datadog-agent/comp/rdnsquerier/def"
	rdnsquerierimplnone "github.com/DataDog/datadog-agent/comp/rdnsquerier/impl-none"
)

// Requires defines the dependencies for the rdnsquerier component
type Requires struct {
	Lifecycle   compdef.Lifecycle
	AgentConfig config.Component
	Logger      log.Component
	Telemetry   telemetry.Component
}

// Provides defines the output of the rdnsquerier component
type Provides struct {
	Comp rdnsquerier.Component
}

const moduleName = "reverse_dns_enrichment"

type rdnsQuerierTelemetry = struct {
	total              telemetry.Counter
	private            telemetry.Counter
	chanAdded          telemetry.Counter
	droppedChanFull    telemetry.Counter
	droppedRateLimiter telemetry.Counter
	invalidIPAddress   telemetry.Counter
	lookupErrNotFound  telemetry.Counter
	lookupErrTimeout   telemetry.Counter
	lookupErrTemporary telemetry.Counter
	lookupErrOther     telemetry.Counter
	successful         telemetry.Counter
}

type rdnsQuerierImpl struct {
	rdnsQuerierConfig *rdnsQuerierConfig
	logger            log.Component
	internalTelemetry *rdnsQuerierTelemetry

	started bool

	querier querier
}

// NewComponent creates a new rdnsquerier component
func NewComponent(reqs Requires) (Provides, error) {
	rdnsQuerierConfig := newConfig(reqs.AgentConfig)
	reqs.Logger.Infof("Reverse DNS Enrichment config: (enabled=%t workers=%d chan_size=%d rate_limiter.enabled=%t rate_limiter.limit_per_sec=%d cache.enabled=%t cache.entry_ttl=%d cache.clean_interval=%d cache.persist_interval=%d)",
		rdnsQuerierConfig.enabled,
		rdnsQuerierConfig.workers,
		rdnsQuerierConfig.chanSize,
		rdnsQuerierConfig.rateLimiterEnabled,
		rdnsQuerierConfig.rateLimitPerSec,
		rdnsQuerierConfig.cacheEnabled,
		rdnsQuerierConfig.cacheEntryTTL,
		rdnsQuerierConfig.cacheCleanInterval,
		rdnsQuerierConfig.cachePersistInterval)

	//JMWDEBUG
	reqs.Logger.Debugf("JMW Reverse DNS Enrichment debug config: (fake_resolver=%t generate_fake_queries=%t lookup_delay_ms=%d)",
		rdnsQuerierConfig.fakeResolver,
		rdnsQuerierConfig.generateFakeQueriesPerSecond,
		rdnsQuerierConfig.lookupDelayMs)
	//JMWDEBUG

	if !rdnsQuerierConfig.enabled {
		return Provides{
			Comp: rdnsquerierimplnone.NewNone().Comp,
		}, nil
	}

	internalTelemetry := &rdnsQuerierTelemetry{
		reqs.Telemetry.NewCounter(moduleName, "total", []string{}, "Counter measuring the total number of rDNS requests"),
		reqs.Telemetry.NewCounter(moduleName, "private", []string{}, "Counter measuring the number of rDNS requests in the private address space"),
		reqs.Telemetry.NewCounter(moduleName, "chan_added", []string{}, "Counter measuring the number of rDNS requests added to the channel"),
		reqs.Telemetry.NewCounter(moduleName, "dropped_chan_full", []string{}, "Counter measuring the number of rDNS requests dropped because the channel was full"),
		reqs.Telemetry.NewCounter(moduleName, "dropped_rate_limiter", []string{}, "Counter measuring the number of rDNS requests dropped because the rate limiter wait failed"),
		reqs.Telemetry.NewCounter(moduleName, "invalid_ip_address", []string{}, "Counter measuring the number of rDNS requests with an invalid IP address"),
		reqs.Telemetry.NewCounter(moduleName, "lookup_err_not_found", []string{}, "Counter measuring the number of rDNS lookups that returned a not found error"),
		reqs.Telemetry.NewCounter(moduleName, "lookup_err_timeout", []string{}, "Counter measuring the number of rDNS lookups that returned a timeout error"),
		reqs.Telemetry.NewCounter(moduleName, "lookup_err_temporary", []string{}, "Counter measuring the number of rDNS lookups that returned a temporary error"),
		reqs.Telemetry.NewCounter(moduleName, "lookup_err_other", []string{}, "Counter measuring the number of rDNS lookups that returned error not otherwise classified"),
		reqs.Telemetry.NewCounter(moduleName, "successful", []string{}, "Counter measuring the number of successful rDNS requests"),
	}

	q := &rdnsQuerierImpl{
		rdnsQuerierConfig: rdnsQuerierConfig,
		logger:            reqs.Logger,
		internalTelemetry: internalTelemetry,

		started: false,
		querier: newQuerier(rdnsQuerierConfig, reqs.Logger, internalTelemetry),
	}

	reqs.Lifecycle.Append(compdef.Hook{
		OnStart: q.start,
		OnStop:  q.stop,
	})

	return Provides{
		Comp: q,
	}, nil
}

// GetHostnameAsync attempts to resolve the hostname for the given IP address.
// If the IP address is invalid then an error is returned.
// If the IP address is not in the private address space then it is ignored - no lookup is performed and no error is returned.
// If the IP address is in the private address space then a reverse DNS lookup request is sent to a channel to be processed asynchronously.
// If the channel is full then an error is returned.
// When the lookup request completes the updateHostname function will be called asynchronously with the results.
// JMWTUE comment when err is added to callback
func (q *rdnsQuerierImpl) GetHostnameAsync(ipAddr []byte, updateHostname func(string)) error {
	q.internalTelemetry.total.Inc()

	netipAddr, ok := netip.AddrFromSlice(ipAddr)
	if !ok {
		q.internalTelemetry.invalidIPAddress.Inc()
		return fmt.Errorf("invalid IP address %v", ipAddr)
	}

	if !netipAddr.IsPrivate() {
		q.logger.Tracef("Reverse DNS Enrichment IP address %s is not in the private address space", netipAddr)
		return nil
	}
	q.internalTelemetry.private.Inc()

	//JMWTUE comment, add sync callback, add error to async callback
	err := q.querier.getHostnameAsync(netipAddr.String(), updateHostname)
	if err != nil {
		q.logger.Debugf("Reverse DNS Enrichment GetHostnameAsync() returned error: %v", err) //JMW?
		//JMW add test for this error - and others
		return err
	}

	return nil
}

func (q *rdnsQuerierImpl) start(_ context.Context) error {
	if q.started {
		q.logger.Debugf("Reverse DNS Enrichment already started")
		return nil
	}

	q.querier.start()
	q.started = true
	return nil
}

func (q *rdnsQuerierImpl) stop(context.Context) error {
	if !q.started {
		q.logger.Debugf("Reverse DNS Enrichment already stopped")
		return nil
	}

	q.querier.stop()
	q.started = false
	return nil
}
