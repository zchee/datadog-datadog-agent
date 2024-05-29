// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

// Package trivy ... /* TODO: detailed doc comment for the component */
package trivy

import (
	"context"

	"github.com/DataDog/datadog-agent/comp/core/config"
	"github.com/DataDog/datadog-agent/comp/core/workloadmeta"
	"github.com/DataDog/datadog-agent/pkg/sbom"
	pkgconfig "github.com/DataDog/datadog-agent/pkg/security/config"
	"github.com/DataDog/datadog-agent/pkg/security/secl/model"
	"github.com/DataDog/datadog-agent/pkg/util/optional"
	"github.com/DataDog/datadog-go/v5/statsd"
)

// team: /* TODO: add team name */

type Check interface{}

// Component is the component type.
type Component interface {
	Factory(store workloadmeta.Component, cfg config.Component) optional.Option[func() Check]
	NewSBOMResolver(_ *pkgconfig.RuntimeSecurityConfig, _ statsd.ClientInterface, _ optional.Option[workloadmeta.Component]) (Resolver, error)
	UpdateSBOMRepoMetadata(sbom *workloadmeta.SBOM, repoTags, repoDigests []string) *workloadmeta.SBOM
	NewScanRequest(imageID string) sbom.ScanRequest
	IsSBOMCollectionIsEnabled() bool
}

var TrivyComponent Component

func GetTrivyComponent() Component {
	return TrivyComponent
}

// Package describes a system package
type Package struct {
	Name       string
	Version    string
	SrcVersion string
}

type Resolver interface {

	// OnCGroupDeletedEvent is used to handle a CGroupDeleted event
	OnCGroupDeletedEvent(_ interface{})

	// OnWorkloadSelectorResolvedEvent is used to handle the creation of a new cgroup with its resolved tags
	OnWorkloadSelectorResolvedEvent(_ interface{})

	// ResolvePackage returns the Package that owns the provided file
	ResolvePackage(_ string, _ *model.FileEvent) *Package

	// SendStats sends stats
	SendStats() error

	// Start starts the goroutine of the SBOM resolver
	Start(_ context.Context)
}

const CheckName = "sbom"
