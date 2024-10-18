// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build test

package server

import (
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/DataDog/datadog-agent/pkg/metrics/event"
	"github.com/DataDog/datadog-agent/pkg/metrics/servicecheck"
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

var healthyMetricTest = eqTest[metrics.MetricSample]{
	{eMetricName, "daemon1"},
	{eMetricValue, 666.0},
	{eMetricType, metrics.CounterType},
}
var healthyMetricAltTest = eqTest[metrics.MetricSample]{
	{eMetricName, "daemon1"},
	{eMetricValue, 123.0},
	{eMetricType, metrics.CounterType},
}
var healthyMetricTaggedTest = eqTest[metrics.MetricSample]{
	{eMetricName, "daemon2"},
	{eMetricValue, 1000.0},
	{eMetricType, metrics.CounterType},
}

var healthyService = []byte("_sc|agent.up|0|d:12345|h:localhost|m:this is fine|#sometag1:somevalyyue1,sometag2:somevalue2")
var healthyServiceTest = eqTest[*servicecheck.ServiceCheck]{
	{eServiceCheckName, "agent.up"},
	{eServiceHostname, "localhost"},
	{eServiceMessage, "this is fine"},
	{eServiceTags, []string{"sometag1:somevalyyue1", "sometag2:somevalue2"}},
	{eServiceStatus, 0},
	{eServiceTs, 12345},
}

type eqSingleTest[T any] struct {
	testFunc      func(*testing.T, T, interface{})
	expectedValue interface{}
}

type eqTest[T any] []eqSingleTest[T]

func (test eqTest[T]) test(t *testing.T, entity T) {
	assert.NotNil(t, entity, "Attempted to run a test on a nil entity")
	for _, singleTest := range test {
		singleTest.testFunc(t, entity, singleTest.expectedValue)
	}
}

func (test eqTest[T]) addTest(testFunc func(*testing.T, T, interface{}), expectedValue interface{}) eqTest[T] {
	newTest := append([]eqSingleTest[T]{}, test...)
	return append(newTest, eqSingleTest[T]{testFunc, expectedValue})
}

type eMetricTest eqTest[metrics.MetricSample]

func eMetricName(t *testing.T, metric metrics.MetricSample, name interface{}) {
	assert.Equal(t, name, metric.Name, "metric name was expected to match")
}
func eMetricValue(t *testing.T, metric metrics.MetricSample, value interface{}) {
	assert.EqualValues(t, value, metric.Value, "metric value was expected to match")
}
func eMetricType(t *testing.T, metric metrics.MetricSample, mtype interface{}) {
	assert.Equal(t, mtype, metric.Mtype, "metric type was expected to match")
}
func eMetricTags(t *testing.T, metric metrics.MetricSample, tags interface{}) {
	assert.ElementsMatch(t, tags, metric.Tags, "metric tags was expected to match")
}
func eMetricSampleRate(t *testing.T, metric metrics.MetricSample, sampleRate interface{}) {
	assert.Equal(t, sampleRate, metric.SampleRate, "metric sample rate was expected to match")
}
func eMetricRawValue(t *testing.T, metric metrics.MetricSample, rawValue interface{}) {
	assert.Equal(t, rawValue, metric.RawValue, "metric raw value was expected to match")
}
func eMetricTimestamp(t *testing.T, metric metrics.MetricSample, timestamp interface{}) {
	assert.EqualValues(t, timestamp, metric.Timestamp, "metric timestamp was expected to match")
}

type eServiceTest eqTest[*servicecheck.ServiceCheck]

func eServiceCheckName(t *testing.T, sc *servicecheck.ServiceCheck, checkName interface{}) {
	assert.Equal(t, checkName, sc.CheckName, "service check name was expected to match")
}
func eServiceHostname(t *testing.T, sc *servicecheck.ServiceCheck, hostname interface{}) {
	assert.Equal(t, hostname, sc.Host, "service hostname was expected to match")
}
func eServiceMessage(t *testing.T, sc *servicecheck.ServiceCheck, message interface{}) {
	assert.Equal(t, message, sc.Message, "service message was expected to match")
}
func eServiceTs(t *testing.T, sc *servicecheck.ServiceCheck, ts interface{}) {
	assert.Equal(t, ts, sc.Ts, "servic timestamp was expected to match")
}
func eServiceTags(t *testing.T, sc *servicecheck.ServiceCheck, tags interface{}) {
	assert.ElementsMatch(t, tags, sc.Tags, "service tags were expected to match")
}
func eServiceStatus(t *testing.T, sc *servicecheck.ServiceCheck, status interface{}) {
	assert.EqualValues(t, status, sc.Status, "service status was expected to match")
}

type eEventTest eqTest[*event.Event]

func eEventTitle(t *testing.T, e event.Event, title interface{}) {
	assert.Equal(t, title, e.Title, "event title was expected to match")
}
func eEventText(t *testing.T, e event.Event, text interface{}) {
	assert.Equal(t, text, e.Text, "event text was expected to match")
}
func eEventTags(t *testing.T, e event.Event, tags interface{}) {
	assert.ElementsMatch(t, tags, e.Tags, "event tags were expected to match")
}
func eEventHost(t *testing.T, e event.Event, host interface{}) {
	assert.Equal(t, host, e.Host, "event host was expected to match")
}
func eEventTs(t *testing.T, e event.Event, ts interface{}) {
	assert.Equal(t, ts, e.Ts, "event timestamp was expected to match")
}
func eEventAlertT(t *testing.T, e event.Event, atype interface{}) {
	assert.Equal(t, atype, e.AlertType, "event alert type was expected to match")
}
func eEventType(t *testing.T, e event.Event, etype interface{}) {
	assert.Equal(t, etype, e.EventType, "event type was expected to match")
}
func eEventPrio(t *testing.T, e event.Event, prio interface{}) {
	assert.Equal(t, prio, e.Priority, "event priority was expected to match")
}
