// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package util

import (
	"context"
	"net"

	"github.com/DataDog/datadog-agent/pkg/util/log"
)

// Mimicking default behaviour of [net/http.Transport] dial() function
var zeroDialer net.Dialer

// func newDialContext(config config.Reader) DialContext {
func newDialContext() dialContext {
	return func(ctx context.Context, network string, addr string) (net.Conn, error) {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			log.Warnf("unable to split host:port of %s", addr)
			return zeroDialer.DialContext(ctx, network, addr)
		}

		if resolver, ok := db[host]; ok {
			path, err := resolver()

			if err != nil {
				return nil, err
			}

			log.Debugf("address %s registered in the Agent name resolver, reaching: %s", addr, path)

			return net.Dial("tcp", path)
		}

		log.Warnf("address not registered in the Agent name resolver: %s", addr)
		return zeroDialer.DialContext(ctx, network, addr)
	}
}
