//go:build trivy

package pluginloader

import (
	"fmt"
	"plugin"

	"github.com/DataDog/datadog-agent/comp/trivy/trivy"
	"github.com/DataDog/datadog-agent/pkg/util/fxutil"
	"go.uber.org/fx"
)

// Module defines the fx options for this component.
func Module() fxutil.Module {
	return fxutil.Component(
		fx.Provide(func() (trivy.Component, error) {
			p, err := plugin.Open("/home/olivier/dev/datadog-agent/comp/trivy/trivy/plugin/plugin.so")
			if err != nil {
				return nil, err
			}
			v, err := p.Lookup("GetComponent")
			if err != nil {
				return nil, err
			}
			f, ok := v.(func() trivy.Component)
			if !ok {
				return nil, fmt.Errorf("GetComponent has not the correc type")
			}
			return f(), nil

		}),
	)
}
