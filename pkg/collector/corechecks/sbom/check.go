// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2022-present Datadog, Inc.

package sbom

import (
	"github.com/DataDog/datadog-agent/comp/core/config"
	"github.com/DataDog/datadog-agent/comp/core/workloadmeta"
	"github.com/DataDog/datadog-agent/comp/trivy/trivy"
	"github.com/DataDog/datadog-agent/pkg/collector/check"
	"github.com/DataDog/datadog-agent/pkg/util/optional"
)

// Factory returns a new check factory
func Factory(store workloadmeta.Component, cfg config.Component) optional.Option[func() check.Check] {
	res := trivy.GetTrivyComponent().Factory(store, cfg)
	var factory trivy.Check
	factory, ok := res.Get()
	if ok {
		return optional.NewOption(func() check.Check {
			return factory.(check.Check)
		})
	}
	return optional.NewNoneOption[func() check.Check]()
}
