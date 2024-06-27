// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

// Package rdnsquerierimpl implements the rdnsquerier component interface
package rdnsquerierimpl

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"time"

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

type rdnsQuery struct {
	addr           string
	updateHostname func(string)
}

type rdnsQuerierImpl struct {
	logger    log.Component
	telemetry telemetry.Component

	config        *rdnsQuerierConfig
	rdnsQueryChan chan *rdnsQuery
	stopChan      chan struct{}
	wg            sync.WaitGroup

	context     context.Context
	rateLimiter rateLimiter
}

// NewComponent creates a new rdnsquerier component
func NewComponent(reqs Requires) (Provides, error) {
	config := newConfig(reqs.AgentConfig, reqs.Logger)
	reqs.Logger.Infof("Reverse DNS Enrichment config: (enabled=%t workers=%d chan_size=%d rate_limiter.enabled=%t rate_limiter.limit=%d rate_limiter.burst=%d cache.enabled=%t cache.entry_ttl=%d cache.clean_interval=%d cache.persist_interval=%d circuit_breaker.enabled=%t circuit_breaker.max_consecutive_failures=%d circuit_breaker.open_duration=%d circuit_breaker.reset_duration=%d debug.generate_fake_hostnames=%t debug.lookup_addr_delay_ms=%d)",
		config.enabled,
		config.workers,
		config.chanSize,
		config.rateLimiterEnabled,
		config.rateLimiterLimit,
		config.rateLimiterBurst,
		config.cacheEnabled,
		config.cacheEntryTTL,
		config.cacheCleanInterval,
		config.cachePersistInterval,
		config.circuitBreakerEnabled,
		config.circuitBreakerMaxConsecutiveFailures,
		config.circuitBreakerOpenDuration,
		config.circuitBreakerResetDuration,
		config.debugGenerateFakeHostnames,
		config.debugLookupAddrDelayMs)

	if !config.enabled {
		return Provides{
			Comp: rdnsquerierimplnone.NewNone().Comp,
		}, nil
	}

	q := &rdnsQuerierImpl{
		logger:    reqs.Logger,
		telemetry: reqs.Telemetry,

		config: config,

		rdnsQueryChan: make(chan *rdnsQuery, config.chanSize),
		stopChan:      make(chan struct{}),

		rateLimiter: newRateLimiter(config),
	}

	reqs.Lifecycle.Append(compdef.Hook{
		OnStart: q.start,
		OnStop:  q.stop,
	})

	return Provides{
		Comp: q,
	}, nil
}

// GetHostname attempts to use reverse DNS lookup to resolve the hostname for the given IP address.
// If the IP address is in the private address space and the lookup is successful then the updateHostname
// function will be called with the hostname.
func (q *rdnsQuerierImpl) GetHostname(ipAddr []byte, updateHostname func(string)) {
	//JMWTELEMETRY count of total calls to GetHostname
	ipaddr, ok := netip.AddrFromSlice(ipAddr)
	if !ok {
		// IP address is invalid
		return
	}

	if !ipaddr.IsPrivate() {
		return
	}

	//JMWTELEMETRY count of private IP addresses
	query := &rdnsQuery{
		addr:           ipaddr.String(),
		updateHostname: updateHostname,
	}
	select {
	case q.rdnsQueryChan <- query:
		//JMWTELEMETRY
		q.logger.Tracef("JMW query for IP address %s added to channel", query.addr)
	default:
		//JMWTELEMETRY
		q.logger.Debugf("JMW channel is full, dropping query for IP address %s", query.addr)
	}
}

func (q *rdnsQuerierImpl) start(ctx context.Context) error {
	q.context = ctx
	for i := 0; i < q.config.workers; i++ {
		q.wg.Add(1)
		go q.worker(i)
	}
	q.logger.Tracef("Started %d rdnsquerier workers", q.config.workers)

	return nil
}

func (q *rdnsQuerierImpl) stop(context.Context) error {
	close(q.stopChan)
	q.wg.Wait()
	q.logger.Infof("Stopped rdnsquerier workers")

	return nil
}

func (q *rdnsQuerierImpl) worker(num int) {
	defer q.wg.Done()
	for {
		select {
		case query := <-q.rdnsQueryChan:
			q.logger.Tracef("worker[%d] processing rdnsQuery for IP address %v", num, query.addr)
			q.getHostname(query)
		case <-q.stopChan:
			return
		}
	}
}

func (q *rdnsQuerierImpl) getHostname(query *rdnsQuery) {
	err := q.rateLimiter.wait(q.context)
	if err != nil {
		//JMWTELEMETRY
		q.logger.Debugf("JMW rateLimiter.Wait() returned error: %v - dropping query for IP address %s", err, query.addr)
		return
	}

	// net.LookupAddr() can return both a non-zero length slice of hostnames and an error, but when
	// using the host C library resolver at most one result will be returned.  So for now, since
	// specifying other DNS resolvers is not supported, if we get an error we know that no valid
	// hostname was returned.
	hostnames, err := net.LookupAddr(query.addr)
	if q.config.debugLookupAddrDelayMs > 0 {
		time.Sleep(time.Duration(q.config.debugLookupAddrDelayMs) * time.Millisecond)
	}
	if err != nil {
		if dnsErr, ok := err.(*net.DNSError); ok {
			if dnsErr.IsNotFound {
				if q.config.debugGenerateFakeHostnames {
					query.updateHostname("fakehostname-" + query.addr)
					return
				}
				q.logger.Tracef("net.LookupAddr returned not found error '%v' for IP address %v", err, query.addr)
				return
			}
			if dnsErr.IsTimeout {
				q.logger.Tracef("net.LookupAddr returned timeout error '%v' for IP address %v", err, query.addr)
				return
			}
			if dnsErr.IsTemporary {
				q.logger.Tracef("net.LookupAddr returned temporary error '%v' for IP address %v", err, query.addr)
				return
			}
		}
		q.logger.Tracef("net.LookupAddr returned unknown error '%v' for IP address %v", err, query.addr)
		return
	}

	if len(hostnames) > 0 { // if !err then there should be at least one, but just to be safe
		query.updateHostname(hostnames[0])
	}
}
