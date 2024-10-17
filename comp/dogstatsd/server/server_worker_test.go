// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build test

package server

import (
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/DataDog/datadog-agent/comp/core/telemetry"
	"github.com/DataDog/datadog-agent/comp/dogstatsd/listeners"
	"github.com/DataDog/datadog-agent/comp/dogstatsd/packets"
	"github.com/DataDog/datadog-agent/pkg/metrics"
	"github.com/DataDog/datadog-agent/pkg/metrics/event"
	"github.com/DataDog/datadog-agent/pkg/metrics/servicecheck"
)

// Run through all of the major metric types and verify both the default and the timestamped flows
func TestMetricTypes(t *testing.T) {
	cfg := make(map[string]interface{})
	cfg["dogstatsd_port"] = listeners.RandomPortName
	deps := fulfillDepsWithConfigOverride(t, cfg)

	baseTest := eMetricTest{
		{eMetricName, "daemon"},
		{eMetricSampleRate, 0.5},
		{eMetricTags, []string{"sometag1:somevalue1", "sometag2:somevalue2"}},
	}

	scenarios := []struct {
		name  string
		input []byte
		value interface{}
		mType metrics.MetricType
	}{
		{
			name:  "Test Gauge",
			input: []byte("daemon:666|g|@0.5|#sometag1:somevalue1,sometag2:somevalue2"),
			value: 666.0,
			mType: metrics.GaugeType,
		},
		{
			name:  "Test Counter",
			input: []byte("daemon:666|c|@0.5|#sometag1:somevalue1,sometag2:somevalue2"),
			value: 666.0,
			mType: metrics.CounterType,
		},
		{
			name:  "Test Histogram",
			input: []byte("daemon:666|h|@0.5|#sometag1:somevalue1,sometag2:somevalue2"),
			value: 666.0,
			mType: metrics.HistogramType,
		},
		{
			name:  "Test Timing",
			input: []byte("daemon:666|ms|@0.5|#sometag1:somevalue1,sometag2:somevalue2"),
			value: 666.0,
			mType: metrics.HistogramType,
		},
		{
			name:  "Test Set",
			input: []byte("daemon:abc|s|@0.5|#sometag1:somevalue1,sometag2:somevalue2"),
			value: "abc",
			mType: metrics.SetType,
		},
	}

	for _, s := range scenarios {
		t.Run(s.name, func(t *testing.T) {
			test := baseTest.addTest(eMetricType, s.mType)

			if _, ok := s.value.(float64); ok {
				test = test.addTest(eMetricValue, s.value)
			} else {
				test = test.addTest(eMetricRawValue, s.value)
			}
			fullInput := append(append(s.input, []byte("|T1658328888\n")...), s.input...)

			timeTest := test.addTest(eMetricTimestamp, 1658328888)
			test = test.addTest(eMetricTimestamp, 0)
			runTestMetrics(t, deps, fullInput, []eMetricTest{test}, []eMetricTest{timeTest})
		})
	}
}

func TestMetricPermutations(t *testing.T) {
	cfg := make(map[string]interface{})
	cfg["dogstatsd_port"] = listeners.RandomPortName
	deps := fulfillDepsWithConfigOverride(t, cfg)

	packet1Test := eMetricTest{
		{eMetricName, "daemon1"},
		{eMetricValue, 666.0},
		{eMetricType, metrics.CounterType},
	}
	packet1AltTest := eMetricTest{
		{eMetricName, "daemon1"},
		{eMetricValue, 123.0},
		{eMetricType, metrics.CounterType},
	}
	packet2Test := eMetricTest{
		{eMetricName, "daemon2"},
		{eMetricValue, 1000.0},
		{eMetricType, metrics.CounterType},
	}

	scenarios := []struct {
		name  string
		input []byte
		tests []eMetricTest
	}{
		{
			name:  "Base multi-metric packet",
			input: []byte("daemon1:666|c\ndaemon2:1000|c"),
			tests: []eMetricTest{packet1Test, packet2Test},
		},
		{
			name:  "Multi-value packet",
			input: []byte("daemon1:666:123|c\ndaemon2:1000|c"),
			tests: []eMetricTest{packet1Test, packet1AltTest, packet2Test},
		},
		{
			name:  "Multi-value packet with skip empty",
			input: []byte("daemon1::666::123::::|c\ndaemon2:1000|c"),
			tests: []eMetricTest{packet1Test, packet1AltTest, packet2Test},
		},
		{
			name:  "Malformed packet",
			input: []byte("daemon1:666|c\n\ndaemon2:1000|c\n"),
			tests: []eMetricTest{packet1Test, packet2Test},
		},
		{
			name:  "Malformed metric",
			input: []byte("daemon1:666a|g\ndaemon2:1000|c|#sometag1:somevalue1,sometag2:somevalue2"),
			tests: []eMetricTest{packet2Test},
		},
		{
			name:  "Empty metric",
			input: []byte("daemon1:|g\ndaemon2:1000|c|#sometag1:somevalue1,sometag2:somevalue2\ndaemon3: :1:|g"),
			tests: []eMetricTest{packet2Test},
		},
	}

	for _, s := range scenarios {
		t.Run(s.name, func(t *testing.T) {
			runTestMetrics(t, deps, s.input, s.tests, []eMetricTest{})
		})
	}
}

func TestHistToDist(t *testing.T) {
	cfg := make(map[string]interface{})
	cfg["dogstatsd_port"] = listeners.RandomPortName
	cfg["histogram_copy_to_distribution"] = true
	cfg["histogram_copy_to_distribution_prefix"] = "dist."
	deps := fulfillDepsWithConfigOverride(t, cfg)

	// Test metric
	input := []byte("daemon:666|h|#sometag1:somevalue1,sometag2:somevalue2")

	test1 := eMetricTest{
		{eMetricName, "daemon"},
		{eMetricValue, 666.0},
		{eMetricType, metrics.HistogramType},
	}

	test2 := eMetricTest{
		{eMetricName, "dist.daemon"},
		{eMetricValue, 666.0},
		{eMetricType, metrics.DistributionType},
	}

	runTestMetrics(t, deps, input, []eMetricTest{test1, test2}, []eMetricTest{})
}

func TestExtraTags(t *testing.T) {
	cfg := make(map[string]interface{})
	cfg["dogstatsd_port"] = listeners.RandomPortName

	deps := fulfillDepsWithConfigOverride(t, cfg)
	deps.Server.SetExtraTags([]string{"sometag3:somevalue3"})

	tests := []eMetricTest{{
		{eMetricName, "daemon"},
		{eMetricValue, 666.0},
		{eMetricType, metrics.GaugeType},
		{eMetricTags, []string{"sometag1:somevalue1", "sometag2:somevalue2", "sometag3:somevalue3"}},
	}}

	// Test single metric
	input := []byte("daemon:666|g|#sometag1:somevalue1,sometag2:somevalue2")
	runTestMetrics(t, deps, input, tests, []eMetricTest{})

	// Test multivalue metric
	tests = append(tests, eMetricTest{
		{eMetricName, "daemon"},
		{eMetricValue, 500.0},
		{eMetricType, metrics.GaugeType},
		{eMetricTags, []string{"sometag1:somevalue1", "sometag2:somevalue2", "sometag3:somevalue3"}},
	})

	input = []byte("daemon:666:500|g|#sometag1:somevalue1,sometag2:somevalue2")
	runTestMetrics(t, deps, input, tests, []eMetricTest{})
}

type batcherMock struct {
	serviceChecks []*servicecheck.ServiceCheck
	events        []*event.Event
	lateSamples   []metrics.MetricSample
	samples       []metrics.MetricSample
}

func (b *batcherMock) appendServiceCheck(serviceCheck *servicecheck.ServiceCheck) {
	b.serviceChecks = append(b.serviceChecks, serviceCheck)
}

func (b *batcherMock) appendEvent(event *event.Event) {
	b.events = append(b.events, event)
}

func (b *batcherMock) appendLateSample(sample metrics.MetricSample) {
	b.lateSamples = append(b.lateSamples, sample)
}

func (b *batcherMock) appendSample(sample metrics.MetricSample) {
	b.samples = append(b.samples, sample)
}

func (b *batcherMock) flush() {
	return
}

func runTestMetrics(t *testing.T, deps serverDeps, input []byte, expTests []eMetricTest, expTimeTests []eMetricTest) {
	s := deps.Server.(*server)
	packet := &packets.Packet{
		Contents:   input,
		Origin:     "test-origin",
		ListenerID: "noop-listener",
		Source:     packets.UDP,
	}
	var b batcherMock
	parser := newParser(deps.Config, s.sharedFloat64List, 1, deps.WMeta, s.stringInternerTelemetry)
	s.parsePackets(&b, parser, []*packets.Packet{packet}, make([]metrics.MetricSample, 0))

	samples := b.samples
	timedSamples := b.lateSamples

	assert.Equal(t, len(expTests), len(samples))
	assert.Equal(t, len(expTimeTests), len(timedSamples))

	for idx, samp := range samples {
		assert.NotNil(t, samp)
		for _, test := range expTests[idx] {
			test.testFunc(t, samp, test.expectedValue)
		}
	}
	for idx, tSamp := range timedSamples {
		assert.NotNil(t, tSamp)
		for _, test := range expTimeTests[idx] {
			test.testFunc(t, tSamp, test.expectedValue)
		}
	}
}

/*
func TestEvents(t *testing.T) {
	cfg := make(map[string]interface{})
	cfg["dogstatsd_port"] = listeners.RandomPortName

	deps := fulfillDepsWithConfigOverride(t, cfg)
	demux := deps.Demultiplexer

	eventOut, _ := demux.GetEventsAndServiceChecksChannels()
	input = []byte("_e{10,10}:test title|test\\ntext|t:warning|d:12345|p:low|h:some.host|k:aggKey|s:source test|#tag1,tag2:test")
	select {
	case res := <-eventOut:
		event := res[0]
		assert.NotNil(t, event)
		assert.ElementsMatch(t, event.Tags, []string{"tag1", "tag2:test"})
	case <-time.After(2 * time.Second):
		assert.FailNow(t, "Timeout on receive channel")
	}

	// Test erroneous Events
	input = []byte("_e{0,9}:|test text\n" +
			"_e{-5,2}:abc\n" +
			"_e{11,10}:test title2|test\\ntext|" +
			"t:warning|d:12345|p:low|h:some.host|k:aggKey|s:source test|#tag1,tag2:test",
		)

	select {
	case res := <-eventOut:
		assert.Equal(t, 1, len(res))
		event := res[0]
		assert.NotNil(t, event)
		assert.Equal(t, event.Title, "test title2")
	case <-time.After(2 * time.Second):
		assert.FailNow(t, "Timeout on receive channel")
	}
}


[]byte("_sc|agent.up|0|d:12345|h:localhost|m:this is fine|#sometag1:somevalyyue1,sometag2:somevalue2")
	select {
	case res := <-serviceOut:
		assert.NotNil(t, res)
	case <-time.After(2 * time.Second):
		assert.FailNow(t, "Timeout on receive channel")
	}


	// Test erroneous Service Check
	_, err = conn.Write([]byte("_sc|agen.down\n_sc|agent.up|0|d:12345|h:localhost|m:this is fine|#sometag1:somevalyyue1,sometag2:somevalue2"))
	require.NoError(t, err, "cannot write to DSD socket")
	select {
	case res := <-serviceOut:
		assert.Equal(t, 1, len(res))
		serviceCheck := res[0]
		assert.NotNil(t, serviceCheck)
		assert.Equal(t, serviceCheck.CheckName, "agent.up")
	case <-time.After(2 * time.Second):
		assert.FailNow(t, "Timeout on receive channel")
	}

	// Test Event
	// ----------


}*/

// Ryan - this seems to go a bit overboard, as mapper has its own tests and we just need to make sure that
// we are calling it when appropriate.
// Update: Sadly it seems I was incorrect about the above. There doesn't seem to be a good way to verify mapper
// was called and tags were integrated outside of what the below is doing. One thing I might be able to squeeze away
// is the test for cache size. TODO revisit
func TestMappingCases(t *testing.T) {
	scenarios := []struct {
		name              string
		config            string
		packets           []string
		expectedSamples   []MetricSample
		expectedCacheSize int
	}{
		{
			name: "Simple OK case",
			config: `
dogstatsd_port: __random__
dogstatsd_mapper_profiles:
  - name: test
    prefix: 'test.'
    mappings:
      - match: "test.job.duration.*.*"
        name: "test.job.duration"
        tags:
          job_type: "$1"
          job_name: "$2"
      - match: "test.job.size.*.*"
        name: "test.job.size"
        tags:
          foo: "$1"
          bar: "$2"
`,
			packets: []string{
				"test.job.duration.my_job_type.my_job_name:666|g",
				"test.job.size.my_job_type.my_job_name:666|g",
				"test.job.size.not_match:666|g",
			},
			expectedSamples: []MetricSample{
				{Name: "test.job.duration", Tags: []string{"job_type:my_job_type", "job_name:my_job_name"}, Mtype: metrics.GaugeType, Value: 666.0},
				{Name: "test.job.size", Tags: []string{"foo:my_job_type", "bar:my_job_name"}, Mtype: metrics.GaugeType, Value: 666.0},
				{Name: "test.job.size.not_match", Tags: nil, Mtype: metrics.GaugeType, Value: 666.0},
			},
			expectedCacheSize: 1000,
		},
		{
			name: "Tag already present",
			config: `
dogstatsd_port: __random__
dogstatsd_mapper_profiles:
  - name: test
    prefix: 'test.'
    mappings:
      - match: "test.job.duration.*.*"
        name: "test.job.duration"
        tags:
          job_type: "$1"
          job_name: "$2"
`,
			packets: []string{
				"test.job.duration.my_job_type.my_job_name:666|g",
				"test.job.duration.my_job_type.my_job_name:666|g|#some:tag",
				"test.job.duration.my_job_type.my_job_name:666|g|#some:tag,more:tags",
			},
			expectedSamples: []MetricSample{
				{Name: "test.job.duration", Tags: []string{"job_type:my_job_type", "job_name:my_job_name"}, Mtype: metrics.GaugeType, Value: 666.0},
				{Name: "test.job.duration", Tags: []string{"job_type:my_job_type", "job_name:my_job_name", "some:tag"}, Mtype: metrics.GaugeType, Value: 666.0},
				{Name: "test.job.duration", Tags: []string{"job_type:my_job_type", "job_name:my_job_name", "some:tag", "more:tags"}, Mtype: metrics.GaugeType, Value: 666.0},
			},
			expectedCacheSize: 1000,
		},
		{
			name: "Cache size",
			config: `
dogstatsd_port: __random__
dogstatsd_mapper_cache_size: 999
dogstatsd_mapper_profiles:
  - name: test
    prefix: 'test.'
    mappings:
      - match: "test.job.duration.*.*"
        name: "test.job.duration"
        tags:
          job_type: "$1"
          job_name: "$2"
`,
			packets:           []string{},
			expectedSamples:   nil,
			expectedCacheSize: 999,
		},
	}

	samples := []metrics.MetricSample{}
	for _, scenario := range scenarios {
		t.Run(scenario.name, func(t *testing.T) {
			deps := fulfillDepsWithConfigYaml(t, scenario.config)

			s := deps.Server.(*server)

			requireStart(t, s)

			assert.Equal(t, deps.Config.Get("dogstatsd_mapper_cache_size"), scenario.expectedCacheSize, "Case `%s` failed. cache_size `%s` should be `%s`", scenario.name, deps.Config.Get("dogstatsd_mapper_cache_size"), scenario.expectedCacheSize)

			var actualSamples []MetricSample
			for _, p := range scenario.packets {
				parser := newParser(deps.Config, s.sharedFloat64List, 1, deps.WMeta, s.stringInternerTelemetry)
				samples, err := s.parseMetricMessage(samples, parser, []byte(p), "", "", false)
				assert.NoError(t, err, "Case `%s` failed. parseMetricMessage should not return error %v", err)
				for _, sample := range samples {
					actualSamples = append(actualSamples, MetricSample{Name: sample.Name, Tags: sample.Tags, Mtype: sample.Mtype, Value: sample.Value})
				}
			}
			for _, sample := range scenario.expectedSamples {
				sort.Strings(sample.Tags)
			}
			for _, sample := range actualSamples {
				sort.Strings(sample.Tags)
			}
			assert.Equal(t, scenario.expectedSamples, actualSamples, "Case `%s` failed. `%s` should be `%s`", scenario.name, actualSamples, scenario.expectedSamples)
		})
	}
}

func TestParseMetricMessageTelemetry(t *testing.T) {
	deps, s := fulfillDepsWithInactiveServer(t, map[string]interface{}{})

	assert.Nil(t, s.mapper)

	var samples []metrics.MetricSample

	parser := newParser(deps.Config, s.sharedFloat64List, 1, deps.WMeta, s.stringInternerTelemetry)

	assert.Equal(t, float64(0), s.tlmProcessedOk.Get())
	samples, err := s.parseMetricMessage(samples, parser, []byte("test.metric:666|g"), "", "", false)
	assert.NoError(t, err)
	assert.Len(t, samples, 1)
	assert.Equal(t, float64(1), s.tlmProcessedOk.Get())

	assert.Equal(t, float64(0), s.tlmProcessedError.Get())
	samples, err = s.parseMetricMessage(samples, parser, nil, "", "", false)
	assert.Error(t, err, "invalid dogstatsd message format")
	assert.Len(t, samples, 1)
	assert.Equal(t, float64(1), s.tlmProcessedError.Get())
}

func TestParseEventMessageTelemetry(t *testing.T) {
	deps, s := fulfillDepsWithInactiveServer(t, map[string]interface{}{})

	parser := newParser(deps.Config, s.sharedFloat64List, 1, deps.WMeta, s.stringInternerTelemetry)

	telemetryMock, ok := deps.Telemetry.(telemetry.Mock)
	assert.True(t, ok)

	// three successful events
	s.parseEventMessage(parser, []byte("_e{10,10}:event title|test\\ntext|c:event-container"), "")
	s.parseEventMessage(parser, []byte("_e{10,10}:event title|test\\ntext|c:event-container"), "")
	s.parseEventMessage(parser, []byte("_e{10,10}:event title|test\\ntext|c:event-container"), "")
	// one error event
	_, err := s.parseEventMessage(parser, nil, "")
	assert.Error(t, err)

	processedEvents, err := telemetryMock.GetCountMetric("dogstatsd", "processed")
	require.NoError(t, err)

	for _, metric := range processedEvents {
		labels := metric.Tags()

		if labels["message_type"] == "events" && labels["state"] == "ok" {
			assert.Equal(t, float64(3), metric.Value())
		}

		if labels["message_type"] == "events" && labels["state"] == "error" {
			assert.Equal(t, float64(1), metric.Value())
		}
	}
}

func TestParseServiceCheckMessageTelemetry(t *testing.T) {
	cfg := make(map[string]interface{})

	cfg["dogstatsd_port"] = listeners.RandomPortName

	deps := fulfillDepsWithConfigOverride(t, cfg)
	s := deps.Server.(*server)

	parser := newParser(deps.Config, s.sharedFloat64List, 1, deps.WMeta, s.stringInternerTelemetry)

	telemetryMock, ok := deps.Telemetry.(telemetry.Mock)
	assert.True(t, ok)

	// three successful events
	s.parseServiceCheckMessage(parser, []byte("_sc|service-check.name|0|c:service-check-container"), "")
	s.parseServiceCheckMessage(parser, []byte("_sc|service-check.name|0|c:service-check-container"), "")
	s.parseServiceCheckMessage(parser, []byte("_sc|service-check.name|0|c:service-check-container"), "")
	// one error event
	_, err := s.parseServiceCheckMessage(parser, nil, "")
	assert.Error(t, err)

	processedEvents, err := telemetryMock.GetCountMetric("dogstatsd", "processed")
	require.NoError(t, err)

	for _, metric := range processedEvents {
		labels := metric.Tags()

		if labels["message_type"] == "service_checks" && labels["state"] == "ok" {
			assert.Equal(t, float64(3), metric.Value())
		}

		if labels["message_type"] == "service_checks" && labels["state"] == "error" {
			assert.Equal(t, float64(1), metric.Value())
		}
	}
}

func TestProcessedMetricsOrigin(t *testing.T) {
	for _, enabled := range []bool{true, false} {
		cfg := make(map[string]interface{})
		cfg["dogstatsd_origin_optout_enabled"] = enabled
		cfg["dogstatsd_port"] = listeners.RandomPortName

		deps := fulfillDepsWithConfigOverride(t, cfg)
		s := deps.Server.(*server)
		assert := assert.New(t)

		s.Stop()

		assert.Len(s.cachedOriginCounters, 0, "this cache must be empty")
		assert.Len(s.cachedOrder, 0, "this cache list must be empty")

		parser := newParser(deps.Config, s.sharedFloat64List, 1, deps.WMeta, s.stringInternerTelemetry)
		samples := []metrics.MetricSample{}
		samples, err := s.parseMetricMessage(samples, parser, []byte("test.metric:666|g"), "test_container", "1", false)
		assert.NoError(err)
		assert.Len(samples, 1)

		// one thing should have been stored when we parse a metric
		samples, err = s.parseMetricMessage(samples, parser, []byte("test.metric:555|g"), "test_container", "1", true)
		assert.NoError(err)
		assert.Len(samples, 2)
		assert.Len(s.cachedOriginCounters, 1, "one entry should have been cached")
		assert.Len(s.cachedOrder, 1, "one entry should have been cached")
		assert.Equal(s.cachedOrder[0].origin, "test_container")

		// when we parse another metric (different value) with same origin, cache should contain only one entry
		samples, err = s.parseMetricMessage(samples, parser, []byte("test.second_metric:525|g"), "test_container", "2", true)
		assert.NoError(err)
		assert.Len(samples, 3)
		assert.Len(s.cachedOriginCounters, 1, "one entry should have been cached")
		assert.Len(s.cachedOrder, 1, "one entry should have been cached")
		assert.Equal(s.cachedOrder[0].origin, "test_container")
		assert.Equal(s.cachedOrder[0].ok, map[string]string{"message_type": "metrics", "state": "ok", "origin": "test_container"})
		assert.Equal(s.cachedOrder[0].err, map[string]string{"message_type": "metrics", "state": "error", "origin": "test_container"})

		// when we parse another metric (different value) but with a different origin, we should store a new entry
		samples, err = s.parseMetricMessage(samples, parser, []byte("test.second_metric:525|g"), "another_container", "3", true)
		assert.NoError(err)
		assert.Len(samples, 4)
		assert.Len(s.cachedOriginCounters, 2, "two entries should have been cached")
		assert.Len(s.cachedOrder, 2, "two entries should have been cached")
		assert.Equal(s.cachedOrder[0].origin, "test_container")
		assert.Equal(s.cachedOrder[0].ok, map[string]string{"message_type": "metrics", "state": "ok", "origin": "test_container"})
		assert.Equal(s.cachedOrder[0].err, map[string]string{"message_type": "metrics", "state": "error", "origin": "test_container"})
		assert.Equal(s.cachedOrder[1].origin, "another_container")
		assert.Equal(s.cachedOrder[1].ok, map[string]string{"message_type": "metrics", "state": "ok", "origin": "another_container"})
		assert.Equal(s.cachedOrder[1].err, map[string]string{"message_type": "metrics", "state": "error", "origin": "another_container"})

		// oldest one should be removed once we reach the limit of the cache
		maxOriginCounters = 2
		samples, err = s.parseMetricMessage(samples, parser, []byte("yetanothermetric:525|g"), "third_origin", "3", true)
		assert.NoError(err)
		assert.Len(samples, 5)
		assert.Len(s.cachedOriginCounters, 2, "two entries should have been cached, one has been evicted already")
		assert.Len(s.cachedOrder, 2, "two entries should have been cached, one has been evicted already")
		assert.Equal(s.cachedOrder[0].origin, "another_container")
		assert.Equal(s.cachedOrder[0].ok, map[string]string{"message_type": "metrics", "state": "ok", "origin": "another_container"})
		assert.Equal(s.cachedOrder[0].err, map[string]string{"message_type": "metrics", "state": "error", "origin": "another_container"})
		assert.Equal(s.cachedOrder[1].origin, "third_origin")
		assert.Equal(s.cachedOrder[1].ok, map[string]string{"message_type": "metrics", "state": "ok", "origin": "third_origin"})
		assert.Equal(s.cachedOrder[1].err, map[string]string{"message_type": "metrics", "state": "error", "origin": "third_origin"})

		// oldest one should be removed once we reach the limit of the cache
		maxOriginCounters = 2
		samples, err = s.parseMetricMessage(samples, parser, []byte("blablabla:555|g"), "fourth_origin", "4", true)
		assert.NoError(err)
		assert.Len(samples, 6)
		assert.Len(s.cachedOriginCounters, 2, "two entries should have been cached, two have been evicted already")
		assert.Len(s.cachedOrder, 2, "two entries should have been cached, two have been evicted already")
		assert.Equal(s.cachedOrder[0].origin, "third_origin")
		assert.Equal(s.cachedOrder[0].ok, map[string]string{"message_type": "metrics", "state": "ok", "origin": "third_origin"})
		assert.Equal(s.cachedOrder[0].err, map[string]string{"message_type": "metrics", "state": "error", "origin": "third_origin"})
		assert.Equal(s.cachedOrder[1].origin, "fourth_origin")
		assert.Equal(s.cachedOrder[1].ok, map[string]string{"message_type": "metrics", "state": "ok", "origin": "fourth_origin"})
		assert.Equal(s.cachedOrder[1].err, map[string]string{"message_type": "metrics", "state": "error", "origin": "fourth_origin"})
	}
}

func TestNextMessage(t *testing.T) {
	scenarios := []struct {
		name              string
		messages          []string
		eolTermination    bool
		expectedTlm       int64
		expectedMetritCnt int
	}{
		{
			name:              "No eol newline, eol enabled",
			messages:          []string{"foo\n", "bar\r\n", "baz\r\n", "quz\n", "hax\r"},
			eolTermination:    true,
			expectedTlm:       1,
			expectedMetritCnt: 4, // final message won't be processed, no newline
		},
		{
			name:              "No eol newline, eol disabled",
			messages:          []string{"foo\n", "bar\r\n", "baz\r\n", "quz\n", "hax"},
			eolTermination:    false,
			expectedTlm:       0,
			expectedMetritCnt: 5,
		},
		{
			name:              "Base Case",
			messages:          []string{"foo\n", "bar\r\n", "baz\r\n", "quz\n", "hax\r\n"},
			eolTermination:    true,
			expectedTlm:       0,
			expectedMetritCnt: 5,
		},
	}

	for _, s := range scenarios {
		t.Run(s.name, func(t *testing.T) {
			packet := []byte(strings.Join(s.messages, ""))
			initialTelem := dogstatsdUnterminatedMetricErrors.Value()
			res := nextMessage(&packet, s.eolTermination)
			cnt := 0
			for res != nil {
				// Confirm newline/carriage return were not transferred
				assert.Equal(t, string(res), strings.TrimRight(s.messages[cnt], "\n\r"))
				res = nextMessage(&packet, s.eolTermination)
				cnt++
			}

			assert.Equal(t, s.expectedTlm, dogstatsdUnterminatedMetricErrors.Value()-initialTelem)
			assert.Equal(t, s.expectedMetritCnt, cnt)
		})
	}
}

type eSingleTest struct {
	testFunc      func(*testing.T, metrics.MetricSample, interface{})
	expectedValue interface{}
}

type eMetricTest []eSingleTest

func (test eMetricTest) addTest(testFunc func(*testing.T, metrics.MetricSample, interface{}), expectedValue interface{}) eMetricTest {
	newTest := append([]eSingleTest{}, test...)
	return append(newTest, eSingleTest{testFunc, expectedValue})
}

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
	assert.Equal(t, sampleRate, metric.SampleRate, "sample rate was expected to match")
}

func eMetricRawValue(t *testing.T, metric metrics.MetricSample, rawValue interface{}) {
	assert.Equal(t, rawValue, metric.RawValue, "metric raw value was expected to match")
}

func eMetricTimestamp(t *testing.T, metric metrics.MetricSample, timestamp interface{}) {
	assert.EqualValues(t, timestamp, metric.Timestamp, "metric timestamp was expected to match")
}

// Merged with the eolparsing test, now in TestNextMessage
//func TestScanLines(t *testing.T)

// Merged with the scanlines test, now in TestNextMessage
//func TestEOLParsing(t *testing.T)

// Origin from message id is extracted via the parser and passed into the enricher for parseMetricMessage,
// but both events and service checks rely on the underlying enrich functions to pull that information.
// This seems to be cuttable, since the parser output not being passed to enrich seems fully covered. TODO revisit
//func TestOrigin(t *testing.T)

// dogstatsd_origin_optout_enabled interactibility is buried deep within the tagger
// and called from the aggregator end of the pipeline. Test shouldn't be necessary
//func TestContainerIDParsing(t *testing.T)
//func testContainerIDParsing(t *testing.T, cfg map[string]interface{})

// TestNewServerExtraTags tests to confirm the pickup of the "tags" field in fargate and its inclusion in extra tags
// TestExtraTags tests to confirm that extra tags is utilized when it should be
//func TestStaticTags(t *testing.T)
