// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

//go:build trivy

package trivyimpl

import (
	"go.uber.org/fx"

	"github.com/DataDog/datadog-agent/comp/core/config"
	"github.com/DataDog/datadog-agent/comp/core/workloadmeta"
	"github.com/DataDog/datadog-agent/comp/trivy/trivy"
	"github.com/DataDog/datadog-agent/comp/trivy/trivy/trivyimpl/containerd"
	"github.com/DataDog/datadog-agent/pkg/sbom"
	"github.com/DataDog/datadog-agent/pkg/sbom/collectors"
	secuconfig "github.com/DataDog/datadog-agent/pkg/security/config"
	"github.com/DataDog/datadog-agent/pkg/util/fxutil"
	"github.com/DataDog/datadog-agent/pkg/util/optional"
	"github.com/DataDog/datadog-go/v5/statsd"
)

// Module defines the fx options for this component.
func Module() fxutil.Module {
	return fxutil.Component(
		fx.Provide(NewTrivy),
	)
}

type trivyImpl struct{}

func (trivyImpl) Factory(store workloadmeta.Component, cfg config.Component) optional.Option[func() trivy.Check] {
	return Factory(store, cfg)
}

func (trivyImpl) NewSBOMResolver(c *secuconfig.RuntimeSecurityConfig, statsdClient statsd.ClientInterface, wmeta optional.Option[workloadmeta.Component]) (trivy.Resolver, error) {
	return NewSBOMResolver(c, statsdClient, wmeta)
}

func (trivyImpl) UpdateSBOMRepoMetadata(sbom *workloadmeta.SBOM, repoTags, repoDigests []string) *workloadmeta.SBOM {
	return UpdateSBOMRepoMetadata(sbom, repoTags, repoDigests)
}

func (trivyImpl) NewScanRequest(imageID string) sbom.ScanRequest {
	return NewScanRequest(imageID)
}

func (trivyImpl) IsSBOMCollectionIsEnabled() bool {
	return true
}

func NewTrivy() trivy.Component {
	// Component initialization
	t := trivyImpl{}
	trivy.TrivyComponent = t

	collectors.RegisterCollector(collectors.HostCollector, &Collector{
		resChan: make(chan sbom.ScanResult, channelSize),
	})

	containerd.RegisterContainerd()
	return t
}
