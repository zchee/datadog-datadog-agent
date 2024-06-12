// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2022-present Datadog, Inc.

package rdnsquerier

import (
	"fmt"
	"net"
	//JMWNOTUSED nfconfig "github.com/DataDog/datadog-agent/comp/netflow/config"
)

/*
type rdnsCacheEntry struct {
	hostname string
	expirationTime int64
	// map of hashes to callback to set hostname
	callbacks map[string]func(string)
}

// RDNSQuerier provides JMW
type RDNSQuerier struct {
	// mutex for JMW
	mutex sync.RWMutex

	// map of ip to hostname and expiration time
 	cache map[string]rdnsCacheEntry
}
*/

// JMWfunc (q *RDNSQuerier) GetHostname(ipAddr []byte) string {
// JMW GetHostname returns the hostname for the given IP address
func GetHostname(ipAddr []byte) string {
	if len(ipAddr) < 1 { // JMW 4?
		// JMWTELEMETRY increment invalid IP address counter
		return ""
	}
	netIP := net.IP(ipAddr)
	if !netIP.IsPrivate() {
		fmt.Printf("JMW GetHostname() IP address `%s` is not private\n", netIP.String())
		return ""
	}

	// JMWTELEMETRY increment private IP address counter
	addr := netIP.String()
	hostnames, err := net.LookupAddr(addr)
	if err != nil {
		//JMWADDLOGGER f.logger.Warnf("JMW Failed to lookup hostname for IP address `%s`: %s", addr, err)
		fmt.Printf("JMW GetHostname() error looking up hostname for IP address `%s`: %s\n", addr, err)
		// JMWTELEMETRY increment metric for failed lookups
		return ""
	} else {
		if len(hostnames) == 0 { // JMW is this even possible?
			fmt.Printf("JMW IP address `%s` has no match - returning empty hostname", addr)
			// JMWTELEMETRY increment metric for no match
			return ""
		}
		// JMWTELEMETRY increment metric for successful lookups
		//if (len(hostnames) > 1) {
		// JMWTELEMETRY increment metric for multiple hostnames
		// JMW trace debug too?
		//}
		fmt.Printf("JMW GetHostname() IP address `%s` matched - returning hostname `%s`\n", addr, hostnames[0])
		return hostnames[0]
	}
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
