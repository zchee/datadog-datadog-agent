// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

// Package rdnsquerierimpl provides ...
package rdnsquerierimpl

import (
	"fmt"

	"go.uber.org/fx"

	"github.com/DataDog/datadog-agent/comp/rdnsquerier"
	"github.com/DataDog/datadog-agent/pkg/util/fxutil"
)

type dependencies struct {
	fx.In
	Lc fx.Lifecycle
}

type provides struct {
	fx.Out

	Comp rdnsquerier.Component
}

// Module defines the fx options for this component.
func Module() fxutil.Module {
	fmt.Printf("JMW in rdnsquerierimpl.Module()\n")
	return fxutil.Component(
		fx.Provide(newRDNSQuerier),
	)
}

// rdnsQuerierImpl provides ...
type rdnsQuerierImpl struct {
	lc fx.Lifecycle
}

func newRDNSQuerier(deps dependencies) provides {
	fmt.Printf("JMW in rdnsquerierimpl.newRDNSQuerier()\n")
	// Component initialization
	querier := &rdnsQuerierImpl{
		lc: deps.Lc,
	}
	return provides{
		Comp: querier,
	}
}

// GetHostname returns the hostname for the given IP address
func (q *rdnsQuerierImpl) GetHostname(ipAddr []byte) string {
	fmt.Printf("JMW in rdnsQuerierImpl.GetHostname()\n")
	return ""
}
