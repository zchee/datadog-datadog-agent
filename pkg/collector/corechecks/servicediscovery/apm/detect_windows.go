// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

// Package apm provides functionality to detect the type of APM instrumentation a service is using.
package apm

import (
	"github.com/DataDog/datadog-agent/pkg/collector/corechecks/servicediscovery/language"
	"github.com/DataDog/datadog-agent/pkg/collector/corechecks/servicediscovery/usm"
)

// detectInternals performs more specialized detection based on the language
func detectInternals(_ int32, _ []string, _ map[string]string, _ language.Language, _ usm.DetectorContextMap) Instrumentation {
	// TODO: Add specialized detectors.
	return None
}
