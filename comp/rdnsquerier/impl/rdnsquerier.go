// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

// Package rdnsquerierimpl implements the rdnsquerier component interface
package rdnsquerierimpl

import (
	"context"
	"net/netip"
	"time"

	"github.com/DataDog/datadog-agent/comp/core/config"
	"github.com/DataDog/datadog-agent/comp/core/log"
	compdef "github.com/DataDog/datadog-agent/comp/def"
	rdnsquerier "github.com/DataDog/datadog-agent/comp/rdnsquerier/def"
	//JMWNOTUSED "github.com/DataDog/datadog-agent/comp/core/log"
	//JMW"github.com/DataDog/datadog-agent/comp/core/config"
	//JMWNOTUSED nfconfig "github.com/DataDog/datadog-agent/comp/netflow/config"
)

// Requires defines the dependencies for the rdnsquerier component
type Requires struct {
	Lifecycle compdef.Lifecycle
	Config    config.Component
	Logger    log.Component
}

// Provides defines the output of the rdnsquerier component
type Provides struct {
	Comp rdnsquerier.Component
}

type rdnsQuerierImpl struct {
	config config.Component
	logger log.Component

	// mutex for JMW
	//JMWmutex sync.RWMutex

	// map of ip to hostname and expiration time
	cache map[string]rdnsCacheEntry
}

// NewComponent creates a new rdnsquerier component
func NewComponent(reqs Requires) (Provides, error) {
	q := &rdnsQuerierImpl{
		config: reqs.Config,
		logger: reqs.Logger,
	}

	reqs.Lifecycle.Append(compdef.Hook{
		OnStart: q.start,
		OnStop:  q.stop,
	})

	return Provides{
		Comp: q,
	}, nil
}

func (q *rdnsQuerierImpl) start(context.Context) error {
	// JMW start workers
	q.logger.Infof("JMWRDNSQ Starting RDNS Querier with JMW workers")
	return nil
}

func (q *rdnsQuerierImpl) stop(context.Context) error {
	q.logger.Infof("JMWRDNSQ Stopping RDNS Querier")
	return nil
}

// GetHostname gets the hostname for the given IP address.  If the IP address is invalid or is not in the private address space then it returns an empty string.
// The initial implementation always returns an empty string.
func (q *rdnsQuerierImpl) GetHostnameEmtyString(_ []byte) string {
	q.logger.Infof("JMWRDNSQ GetHostname() - returning empty string")
	return ""
}

// JMWNEXT-----------------------------------------------------------------------------------------------------------------------
type rdnsCacheEntry struct {
	//JMWhostname string
	//JMWUNUSED expirationTime int64
	// map of hashes to callback to set hostname
	//JMWcallbacks map[string]func(string)
}

func (q *rdnsQuerierImpl) timer(name string) func() {
	start := time.Now()
	return func() {
		q.logger.Infof("[timer] %s: took %v usec\n", name, time.Since(start).Microseconds())
	}
}

// GetHostname gets the hostname for the given IP address, if the IP address is in the private address space.
func (q *rdnsQuerierImpl) GetHostname(ipAddr []byte) string {
	defer q.timer("timer JMW GetHostname() all")()

	ipaddr, ok := netip.AddrFromSlice(ipAddr)
	if !ok {
		q.logger.Infof("JMW GetHostname() IP address is invalid\n")
		// JMWTELEMETRY increment invalid IP address counter
		return ""
	}

	if !ipaddr.IsPrivate() {
		q.logger.Infof("JMW GetHostname() IP address `%s` is not private\n", ip.String())
		// JMWTELEMETRY increment NOT private IP address counter
		return ""
	}

	// JMWTELEMETRY increment private IP address counter
	addr := ipaddr.String()

	// JMW LookupAddr can return both a non-zero length slice of hostnames and an error.
	// BUT When using the host C library resolver, at most one result will be returned.
	// So for now, when specifying DNS resolvers is not supported, if we get an error we know that there is no valid hostname returned.
	// If/when we add support for specifying DNS resolvers, there may be multiple hostnames returned, and there may be one or more hostname returned AT THE SAME TIME an error is returned.  To keep it simple, if there is no error, we will just return the first hostname, and if there is an error, we will return an empty string and add telemetry about the error.
	defer q.timer("JMW GetHostname() LookupAddr")()
	hostnames, err := net.LookupAddr(addr)
	if err != nil {
		//JMWADDLOGGER f.logger.Warnf("JMW Failed to lookup hostname for IP address `%s`: %s", addr, err)
		q.logger.Infof("JMW GetHostname() error looking up hostname for IP address `%s`: %v\n", addr, err)
		// JMWTELEMETRY increment metric for failed lookups - JMW should I differentiate between no match and other errors? or just tag w/ error?  how to tag w/ error w/out the tag being a string (unlimited cardinality)?
		return ""
	}

	if len(hostnames) == 0 { // JMW is this even possible? // JMWRM?
		q.logger.Infof("JMW IP address `%s` has no match - returning empty hostname", addr)
		// JMWTELEMETRY increment metric for no match
		return ""
	}

	// JMWTELEMETRY increment metric for successful lookups
	//if (len(hostnames) > 1) {
	// JMWTELEMETRY increment metric for multiple hostnames
	//}
	q.logger.Infof("JMW GetHostname() IP address `%s` matched - returning hostname `%s`\n", addr, hostnames[0])
	return hostnames[0]
}

/*
// JMW Get returns the hostname for the given IP address
func (q *rdnsquerier) Get(ip string) string {
	entry, ok := q.cache[ip]
	if ok && entry.expirationTime < time.Now().Unix() {
		return entry.hostname
	}

	return entry.hostname
}
*/

/* JMWASYNC
func (q *rdnsquerier) GetAsync(ip string, func inlineCallback(string), func asyncCallback(string)) {
	entry, ok := q.cache[ip]
	if ok {
		if entry.expirationTime < time.Now().Unix() {
			inlineCallback(entry)
		}
		return
	}
	if entry.expirationTime < time.Now().Unix() {
		func()
		return
	}
	asyncCallback(entry.hostname)
}
*/

/*
type reverseDNSCache struct {
	// JMW IP address to hostname
	cache map[string]string

	// JMW mutex for cache
	mutex sync.RWMutex
}

func NewReverseDNSCache func() *reverseDNSCache {
	return &reverseDNSCache{
		cache: make(map[string]string),
	}
}

func (r *reverseDNSCache) PreFetch(ip string) string {
}
func (r *reverseDNSCache) Expire() string {
}
func (r *reverseDNSCache) TryGet(ip string) (string, bool) {
}
*/
