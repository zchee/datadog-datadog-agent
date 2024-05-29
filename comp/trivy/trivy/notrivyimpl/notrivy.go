//go:build linux && !trivy

package notrivyimpl

import (
	"github.com/DataDog/datadog-agent/comp/core/config"
	"github.com/DataDog/datadog-agent/comp/core/workloadmeta"
	"github.com/DataDog/datadog-agent/comp/trivy/trivy"
	"github.com/DataDog/datadog-agent/pkg/collector/check"
	"github.com/DataDog/datadog-agent/pkg/sbom"
	secconfig "github.com/DataDog/datadog-agent/pkg/security/config"
	"github.com/DataDog/datadog-agent/pkg/util/fxutil"
	"github.com/DataDog/datadog-agent/pkg/util/optional"
	"github.com/DataDog/datadog-go/v5/statsd"
	"go.uber.org/fx"
)

// Module defines the fx options for this component.
func Module() fxutil.Module {
	return fxutil.Component(
		fx.Provide(newTrivy),
	)
}

type trivyImpl struct{}

func (trivyImpl) Factory(store workloadmeta.Component, cfg config.Component) optional.Option[func() trivy.Check] {
	return optional.NewNoneOption[func() trivy.Check]()
}

func (trivyImpl) NewSBOMResolver(cfg *secconfig.RuntimeSecurityConfig, client statsd.ClientInterface, wmeta optional.Option[workloadmeta.Component]) (trivy.Resolver, error) {
	return NewSBOMResolver(cfg, client, wmeta)
}

func (trivyImpl) UpdateSBOMRepoMetadata(sbom *workloadmeta.SBOM, repoTags, repoDigests []string) *workloadmeta.SBOM {
	return UpdateSBOMRepoMetadata(sbom, repoTags, repoDigests)
}

func (trivyImpl) NewScanRequest(imageID string) sbom.ScanRequest {
	panic("Should not be called because IsSBOMCollectionIsEnabled() return false")
}

func (trivyImpl) IsSBOMCollectionIsEnabled() bool {
	return false
}

func newTrivy() trivy.Component {
	// Component initialization
	t := trivyImpl{}
	trivy.TrivyComponent = t

	return t
}
