// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build test

package server

import (
	"runtime"
	"testing"

	"github.com/DataDog/datadog-agent/pkg/util/testutil/flake"

	"go.uber.org/fx"

	"github.com/DataDog/datadog-agent/comp/aggregator/demultiplexer"
	"github.com/DataDog/datadog-agent/comp/aggregator/demultiplexer/demultiplexerimpl"
	"github.com/DataDog/datadog-agent/comp/core"
	configComponent "github.com/DataDog/datadog-agent/comp/core/config"
	"github.com/DataDog/datadog-agent/comp/core/hostname/hostnameimpl"
	log "github.com/DataDog/datadog-agent/comp/core/log/def"
	logmock "github.com/DataDog/datadog-agent/comp/core/log/mock"
	"github.com/DataDog/datadog-agent/comp/core/telemetry"
	"github.com/DataDog/datadog-agent/comp/core/telemetry/telemetryimpl"
	workloadmeta "github.com/DataDog/datadog-agent/comp/core/workloadmeta/def"
	workloadmetafxmock "github.com/DataDog/datadog-agent/comp/core/workloadmeta/fx-mock"
	"github.com/DataDog/datadog-agent/comp/dogstatsd/pidmap"
	"github.com/DataDog/datadog-agent/comp/dogstatsd/pidmap/pidmapimpl"
	replay "github.com/DataDog/datadog-agent/comp/dogstatsd/replay/def"
	replaymock "github.com/DataDog/datadog-agent/comp/dogstatsd/replay/fx-mock"
	serverdebug "github.com/DataDog/datadog-agent/comp/dogstatsd/serverDebug"
	"github.com/DataDog/datadog-agent/comp/dogstatsd/serverDebug/serverdebugimpl"
	"github.com/DataDog/datadog-agent/comp/serializer/compression/compressionimpl"
	"github.com/DataDog/datadog-agent/pkg/metrics"
	"github.com/DataDog/datadog-agent/pkg/util/fxutil"
	"github.com/DataDog/datadog-agent/pkg/util/optional"
)

// This is a copy of the serverDeps struct, but without the server field.
// We need this to avoid starting multiple server with the same test.
type depsWithoutServer struct {
	fx.In

	Config        configComponent.Component
	Log           log.Component
	Demultiplexer demultiplexer.FakeSamplerMock
	Replay        replay.Component
	PidMap        pidmap.Component
	Debug         serverdebug.Component
	WMeta         optional.Option[workloadmeta.Component]
	Telemetry     telemetry.Component
}

type serverDeps struct {
	fx.In

	Config        configComponent.Component
	Log           log.Component
	Demultiplexer demultiplexer.FakeSamplerMock
	Replay        replay.Component
	PidMap        pidmap.Component
	Debug         serverdebug.Component
	WMeta         optional.Option[workloadmeta.Component]
	Telemetry     telemetry.Component
	Server        Component
}

func fulfillDeps(t testing.TB) serverDeps {
	return fulfillDepsWithConfigOverride(t, map[string]interface{}{})
}

func fulfillDepsWithConfigOverride(t testing.TB, overrides map[string]interface{}) serverDeps {
	// TODO: https://datadoghq.atlassian.net/browse/AMLII-1948
	if runtime.GOOS == "darwin" {
		flake.Mark(t)
	}
	return fxutil.Test[serverDeps](t, fx.Options(
		core.MockBundle(),
		serverdebugimpl.MockModule(),
		fx.Replace(configComponent.MockParams{
			Overrides: overrides,
		}),
		replaymock.MockModule(),
		compressionimpl.MockModule(),
		pidmapimpl.Module(),
		demultiplexerimpl.FakeSamplerMockModule(),
		workloadmetafxmock.MockModule(workloadmeta.NewParams()),
		Module(Params{Serverless: false}),
	))
}

func fulfillDepsWithConfigYaml(t testing.TB, yaml string) serverDeps {
	return fxutil.Test[serverDeps](t, fx.Options(
		fx.Provide(func(t testing.TB) log.Component { return logmock.New(t) }),
		fx.Provide(func(t testing.TB) configComponent.Component { return configComponent.NewMockFromYAML(t, yaml) }),
		telemetryimpl.MockModule(),
		hostnameimpl.MockModule(),
		serverdebugimpl.MockModule(),
		replaymock.MockModule(),
		compressionimpl.MockModule(),
		pidmapimpl.Module(),
		demultiplexerimpl.FakeSamplerMockModule(),
		workloadmetafxmock.MockModule(workloadmeta.NewParams()),
		Module(Params{Serverless: false}),
	))
}

// Returns a server that is not started along with associated dependencies
// Be careful when using this functionality, as server start instantiates many internal components
func fulfillDepsWithInactiveServer(t *testing.T, cfg map[string]interface{}) (depsWithoutServer, *server) {
	deps := fxutil.Test[depsWithoutServer](t, fx.Options(
		core.MockBundle(),
		serverdebugimpl.MockModule(),
		fx.Replace(configComponent.MockParams{
			Overrides: cfg,
		}),
		fx.Supply(Params{Serverless: false}),
		replaymock.MockModule(),
		compressionimpl.MockModule(),
		pidmapimpl.Module(),
		demultiplexerimpl.FakeSamplerMockModule(),
		workloadmetafxmock.MockModule(workloadmeta.NewParams()),
	))

	s := newServerCompat(deps.Config, deps.Log, deps.Replay, deps.Debug, false, deps.Demultiplexer, deps.WMeta, deps.PidMap, deps.Telemetry)

	return deps, s
}

type MetricSample struct {
	Name  string
	Value float64
	Tags  []string
	Mtype metrics.MetricType
}
