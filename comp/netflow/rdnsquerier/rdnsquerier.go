// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2022-present Datadog, Inc.

package rdnsquerier

import (
	"fmt"
	"net"
	"time"
	//JMWNOTUSED nfconfig "github.com/DataDog/datadog-agent/comp/netflow/config"
)

type rdnsCacheEntry struct {
	//JMWhostname String
	expirationTime int64
	// map of hashes to callback to set hostname
	//JMWcallbacks map[string]func(string)
}

// RDNSQuerier provides JMW
type RDNSQuerier struct {
	// mutex for JMW
	//JMWmutex sync.RWMutex

	// map of ip to hostname and expiration time
	cache map[string]rdnsCacheEntry
}

func NewRDNSQuerier() *RDNSQuerier {
	return &RDNSQuerier{
		cache: make(map[string]rdnsCacheEntry),
	}
}

func timer(name string) func() {
	start := time.Now()
	return func() {
		fmt.Printf("%s: took %v usec\n", name, time.Since(start).Microseconds())
	}
}

// JMWfunc (q *RDNSQuerier) GetHostname(ipAddr []byte) string {
// JMW GetHostname returns the hostname for the given IP address
func (q *RDNSQuerier) GetHostname(ipAddr []byte) string {
	defer timer("timer JMW GetHostname() all")()

	ip := net.IP(ipAddr)
	if !ip.IsPrivate() {
		fmt.Printf("JMW GetHostname() IP address `%s` is not private\n", ip.String())
		// JMWTELEMETRY increment NOT private IP address counter
		return ""
	}

	// JMWTELEMETRY increment private IP address counter
	addr := ip.String()
	// JMW LookupAddr can return both a non-zero length slice of hostnames and an error.
	// BUT When using the host C library resolver, at most one result will be returned.
	// So for now, when specifying DNS resolvers is not supported, if we get an error we know that there is no valid hostname returned.
	// If/when we add support for specifying DNS resolvers, there may be multiple hostnames returned, and there may be one or more hostname returned AT TEH SAME TIME an error is returned.  To keep it simple, if there is no error, we will just return the first hostname, and if there is an error, we will return an empty string and add telemetry about the error.
	defer timer("timer JMW GetHostname() LookupAddr")()
	hostnames, err := net.LookupAddr(addr)
	if err != nil {
		//JMWADDLOGGER f.logger.Warnf("JMW Failed to lookup hostname for IP address `%s`: %s", addr, err)
		fmt.Printf("JMW GetHostname() error looking up hostname for IP address `%s`: %s\n", addr, err)
		// JMWTELEMETRY increment metric for failed lookups - JMW should I differentiate between no match and other errors? or just tag w/ error?  how to tag w/ error w/out the tag being a string (unlimited cardinality)?
		return ""
	}

	if len(hostnames) == 0 { // JMW is this even possible? // JMWRM?
		fmt.Printf("JMW IP address `%s` has no match - returning empty hostname", addr)
		// JMWTELEMETRY increment metric for no match
		return ""
	}

	// JMWTELEMETRY increment metric for successful lookups
	//if (len(hostnames) > 1) {
	// JMWTELEMETRY increment metric for multiple hostnames
	//}
	fmt.Printf("JMW GetHostname() IP address `%s` matched - returning hostname `%s`\n", addr, hostnames[0])
	return hostnames[0]
}

/*
// JMW Get returns the hostname for the given IP address
func (q *RDNSQuerier) Get(ip string) string {
	entry, ok := q.cache[ip]
	if ok && entry.expirationTime < time.Now().Unix() {
		return entry.hostname
	}

	return entry.hostname
}
*/

/* JMWASYNC
func (q *RDNSQuerier) GetAsync(ip string, func inlineCallback(string), func asyncCallback(string)) {
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
