// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

//JMWDEBUG

package rdnsquerierimpl

import (
	"fmt"
	"math/rand"
	"net"
	"time"

	"go.uber.org/atomic"

	"github.com/DataDog/datadog-agent/comp/core/config"
)

type debugConfig struct {
	fakeResolver                    bool
	generateFakeQueriesPerSecond    int
	generateFakeQueriesInjectErrors bool
	lookupDelayMs                   int
	fakeNErrors                     int
	everyMQueries                   int
}

func (c *rdnsQuerierConfig) getDebugConfig(agentConfig config.Component) {
	c.debug.fakeResolver = agentConfig.GetBool("reverse_dns_enrichment.fake_resolver")
	c.debug.generateFakeQueriesPerSecond = agentConfig.GetInt("reverse_dns_enrichment.generate_fake_queries_per_second")
	c.debug.generateFakeQueriesInjectErrors = agentConfig.GetBool("reverse_dns_enrichment.generate_fake_queries_inject_errors")
	c.debug.lookupDelayMs = agentConfig.GetInt("reverse_dns_enrichment.lookup_delay_ms")
	c.debug.fakeNErrors = agentConfig.GetInt("reverse_dns_enrichment.fake_n_errors")
	c.debug.everyMQueries = agentConfig.GetInt("reverse_dns_enrichment.every_m_queries")
}

func (q *rdnsQuerierImpl) logDebugConfig() {
	q.logger.Debugf("JMW Reverse DNS Enrichment debug config: (fake_resolver=%t generate_fake_queries_per_second=%d generate_fake_queries_inject_errors=%t lookup_delay_ms=%d fake_n_errors=%d every_m_queries=%d)",
		q.config.debug.fakeResolver,
		q.config.debug.generateFakeQueriesPerSecond,
		q.config.debug.generateFakeQueriesInjectErrors,
		q.config.debug.lookupDelayMs,
		q.config.debug.fakeNErrors,
		q.config.debug.everyMQueries,
	)
}

func (q *rdnsQuerierImpl) startGenerateFakeQueries() {
	q.logDebugConfig()
	if q.config.debug.generateFakeQueriesPerSecond > 0 {
		go q.generateFakeQueries()
	}
}

func (q *rdnsQuerierImpl) generateFakeQueries() {
	exit := make(chan struct{})
	for {
		select {
		case <-exit:
			return
		case <-time.After(time.Second):
			q.logger.Debugf("JMWDEBUG Reverse DNS Enrichment generating %d fake queries", q.config.debug.generateFakeQueriesPerSecond)
			for range q.config.debug.generateFakeQueriesPerSecond {
				x := rand.Intn(16)
				y := rand.Intn(256)
				z := rand.Intn(256)
				err := q.GetHostname(
					[]byte{10, byte(x), byte(y), byte(z)},
					func(hostname string) {
						// sync callback
						expectedHostname := fmt.Sprintf("fakehostname-10.%d.%d.%d", x, y, z)
						if q.config.debug.generateFakeQueriesInjectErrors && y >= 10 && y < 40 {
							expectedHostname = ""
						}
						if hostname != expectedHostname {
							q.logger.Debugf("JMWDEBUG Reverse DNS Enrichment generateFakeQueries() - sync callback hostname %s DOES NOT MATCH expected %s", hostname, expectedHostname)
						}
					},
					func(hostname string, _ error) {
						// async callback
						expectedHostname := fmt.Sprintf("fakehostname-10.%d.%d.%d", x, y, z)
						if q.config.debug.generateFakeQueriesInjectErrors && y >= 10 && y < 40 {
							expectedHostname = ""
						}
						if hostname != expectedHostname {
							q.logger.Debugf("JMWDEBUG Reverse DNS Enrichment generateFakeQueries() - sync callback hostname %s DOES NOT MATCH expected %s", hostname, expectedHostname)
						}
					},
				)
				if err != nil {
					q.logger.Debugf("JMWDEBUG Reverse DNS Enrichment generateFakeQueries() - GetHostnameAsync() returned error: %v", err)
				}
			}
		}
	}
}

// Fake resolver for debug and test purposes
type resolverFake struct {
	config              *rdnsQuerierConfig
	queryCounter        *atomic.Int32
	fakeErrorsRemaining *atomic.Int32
}

func newResolverFake(config *rdnsQuerierConfig) *resolverFake {
	return &resolverFake{
		config:              config,
		queryCounter:        atomic.NewInt32(0),
		fakeErrorsRemaining: atomic.NewInt32(0),
	}
}
func (r *resolverFake) lookup(addr string) (string, error) {
	if r.config.debug.lookupDelayMs > 0 {
		time.Sleep(time.Duration(r.config.debug.lookupDelayMs) * time.Millisecond)
	}

	if r.config.debug.generateFakeQueriesInjectErrors {
		// return errors for some of the queries
		netAddr := net.ParseIP(addr)
		if netAddr[14] >= 10 && netAddr[14] < 20 {
			return "", &net.DNSError{Err: "no such host", IsNotFound: true}
		}
		if netAddr[14] >= 20 && netAddr[14] < 30 {
			return "", &net.DNSError{Err: "test timeout error", IsTimeout: true}
		}
		if netAddr[14] >= 30 && netAddr[14] < 40 {
			return "", &net.DNSError{Err: "test temporary error", IsTemporary: true}
		}
	}

	if r.config.debug.everyMQueries > 0 {
		count := r.queryCounter.Inc()

		if count%int32(r.config.debug.everyMQueries) == 0 {
			r.fakeErrorsRemaining.Store(int32(r.config.debug.fakeNErrors))
		}

		remaining := r.fakeErrorsRemaining.Load()
		if remaining > 0 {
			val := r.fakeErrorsRemaining.Dec()
			if val >= 0 {
				return "", &net.DNSError{Err: "test timeout error", IsTimeout: true}
			}
			r.fakeErrorsRemaining.Inc()
			// fall thru
		}
	}

	return "fakehostname-" + addr, nil
}
