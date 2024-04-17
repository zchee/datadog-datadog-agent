// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package multilineexperiment

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/DataDog/datadog-agent/pkg/config"
	"github.com/DataDog/datadog-agent/pkg/logs/message"
)

func TestClusterTable(t *testing.T) {
	config.Datadog.SetWithoutSource("logs_config.multi_line_experiment.enabled", true)
	defer config.Datadog.SetWithoutSource("logs_config.multi_line_experiment.enabled", false)

	d := NewMultiLineDetector()

	d.ProcessMesage(toMessage("abc 123"))
	d.ProcessMesage(toMessage("def 456"))
	d.ProcessMesage(toMessage("123 abc"))
	d.ProcessMesage(toMessage("456 def"))

	d.FoundMultiLineLog(true)

	assert.Equal(t, len(d.clusterTable), 2)
	assert.Equal(t, d.clusterTable[0].score, 2)
	assert.Equal(t, d.clusterTable[1].score, 2)
}

func TestPayloadMultiLineMatch(t *testing.T) {
	config.Datadog.SetWithoutSource("logs_config.multi_line_experiment.enabled", true)
	defer config.Datadog.SetWithoutSource("logs_config.multi_line_experiment.enabled", false)

	d := NewMultiLineDetector()

	d.ProcessMesage(toMessage("abc 123"))
	d.ProcessMesage(toMessage("abc 123"))
	d.ProcessMesage(toMessage("abc 123"))
	d.ProcessMesage(toMessage("abc 123"))
	d.ProcessMesage(toMessage("456 abc"))
	d.ProcessMesage(toMessage("asdfasdf123123"))

	d.FoundMultiLineLog(true)
	payload := d.buildPayload()

	assert.Equal(t, payload.Clusters, 3)
	assert.Equal(t, payload.DroppedClusters, 0)
	assert.Equal(t, payload.Confidence, 0.8)
	assert.Equal(t, payload.DetectedMultiLineLog, true)
	assert.Equal(t, payload.MixedFormatLikely, false)
	assert.Equal(t, payload.TopMatch.Tokens, "CCC DDD")
	assert.Equal(t, payload.TopMatch.Score, 4)
}

func TestPayloadMixedFormat(t *testing.T) {
	config.Datadog.SetWithoutSource("logs_config.multi_line_experiment.enabled", true)
	defer config.Datadog.SetWithoutSource("logs_config.multi_line_experiment.enabled", false)

	d := NewMultiLineDetector()

	d.ProcessMesage(toMessage("abc 123"))
	d.ProcessMesage(toMessage("abc 123"))
	d.ProcessMesage(toMessage("abc 123"))
	d.ProcessMesage(toMessage("456 abc"))
	d.ProcessMesage(toMessage("456 abc"))
	d.ProcessMesage(toMessage("asdfasdf123123"))

	d.FoundMultiLineLog(false)
	payload := d.buildPayload()

	assert.Equal(t, payload.Clusters, 3)
	assert.Equal(t, payload.DroppedClusters, 0)
	assert.Equal(t, payload.Confidence, 0.6)
	assert.Equal(t, payload.DetectedMultiLineLog, false)
	assert.Equal(t, payload.MixedFormatLikely, true)
	assert.Equal(t, payload.TopMatch.Tokens, "CCC DDD")
	assert.Equal(t, payload.TopMatch.Score, 3)
}

func toMessage(s string) *message.Message {
	return message.NewMessage([]byte(s), nil, "info", 0)
}
