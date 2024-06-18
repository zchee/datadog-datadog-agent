// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

//go:build test

package rdnsquerierimpl

import (
	"fmt"

	"go.uber.org/fx"

	"github.com/DataDog/datadog-agent/pkg/util/fxutil"
)

// MockModule defines the fx options for the mock component.
func MockModule() fxutil.Module {
	fmt.Printf("JMW in rdnsquerierimpl.MockModule()\n")
	return fxutil.Component(
		fx.Provide(newMock),
	)
}

type rdnsQuerierMock struct{}

func (q *rdnsQuerierMock) GetHostname(_ []byte) string {
	fmt.Printf("JMW in rdnsQuerierMock.GetHostname()\n")
	return ""
}

func newMock() provides {
	fmt.Printf("JMW in rdnsquerierimpl.newMock()\n")
	// Mock initialization
	return provides{
		Comp: &rdnsQuerierMock{},
	}
}
