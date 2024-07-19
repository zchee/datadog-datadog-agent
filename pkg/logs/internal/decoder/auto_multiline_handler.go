// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package decoder

import (
	"time"

	automultilinedetection "github.com/DataDog/datadog-agent/pkg/logs/internal/decoder/auto_multiline_detection"
	"github.com/DataDog/datadog-agent/pkg/logs/message"
)

// AutoMultilineHandler aggreagates multiline logs.
type AutoMultilineHandler struct {
	labler       *automultilinedetection.Labeler
	aggreagateor *automultilinedetection.Aggregator
}

// NewAutoMultilineHandler creates a new auto multiline handler.
func NewAutoMultilineHandler(outputFn func(m *message.Message), maxContentSize int) *AutoMultilineHandler {

	// Order is important
	heuristics := []automultilinedetection.Heuristic{
		automultilinedetection.NewJSONDetector(),
	}

	return &AutoMultilineHandler{
		labler:       automultilinedetection.NewLabler(heuristics),
		aggreagateor: automultilinedetection.NewAggregator(outputFn, maxContentSize),
	}
}

func (m *AutoMultilineHandler) process(msg *message.Message) {
	label := m.labler.Label(msg.GetContent())
	m.aggreagateor.Aggregate(msg, label)
}

func (m *AutoMultilineHandler) flushChan() <-chan time.Time {
	return nil
}

func (m *AutoMultilineHandler) flush() {
	m.aggreagateor.Flush()
}
