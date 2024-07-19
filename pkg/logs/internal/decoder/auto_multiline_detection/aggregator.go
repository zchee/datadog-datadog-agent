// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

// Package automultilinedetection contains auto multiline detection and aggregation logic.
package automultilinedetection

import (
	"bytes"

	"github.com/DataDog/datadog-agent/pkg/logs/message"
)

type bucket struct {
	message   *message.Message
	buffer    *bytes.Buffer
	lineCount int
}

func (b *bucket) add(msg *message.Message) {
	if b.message == nil {
		b.message = msg
	}
	if b.buffer.Len() > 0 {
		b.buffer.Write(message.EscapedLineFeed)
	}
	b.buffer.Write(msg.GetContent())
	b.lineCount++
}

func (b *bucket) isEmpty() bool {
	return b.message == nil
}

func (b *bucket) flush() *message.Message {
	defer func() {
		b.buffer.Reset()
		b.message = nil
		b.lineCount = 0
	}()

	originalLen := b.buffer.Len()
	data := bytes.TrimSpace(b.buffer.Bytes())
	content := make([]byte, len(data))
	copy(content, data)

	if b.lineCount > 1 {
		return message.NewRawMultiLineMessage(content, b.message.Status, originalLen, b.message.ParsingExtra.Timestamp)
	} else {
		return message.NewRawMessage(content, b.message.Status, originalLen, b.message.ParsingExtra.Timestamp)
	}
}

// Aggregator aggregates multiline logs.
type Aggregator struct {
	outputFn       func(m *message.Message)
	bucket         *bucket
	maxContentSize int
}

// NewAggregator creates a new aggregator.
func NewAggregator(outputFn func(m *message.Message), maxContentSize int) *Aggregator {
	return &Aggregator{
		outputFn:       outputFn,
		bucket:         &bucket{buffer: bytes.NewBuffer(nil)},
		maxContentSize: maxContentSize,
	}
}

// Aggregate aggregates a multiline log using a label.
func (a *Aggregator) Aggregate(msg *message.Message, label Label) {

	// If `noAggregate` - flush the bucket immediately and then flush the next message.
	if label == noAggregate {
		a.Flush()
		a.outputFn(msg)
		return
	}

	// If `aggregate` and the bucket is empty - flush the next message.
	if label == aggregate && a.bucket.isEmpty() {
		a.outputFn(msg)
		return
	}

	// If `startGroup` - flush the bucket.
	if label == startGroup {
		a.Flush()
	}

	// At this point we either have `startGroup` with an empty bucket or `aggregate` with a non-empty bucket
	// so we add the message to the bucket

	if msg.RawDataLen+a.bucket.buffer.Len() >= a.maxContentSize {
		a.bucket.flush()
	}

	a.bucket.add(msg)
}

// Flush flushes the aggregator.
func (a *Aggregator) Flush() {
	if a.bucket.isEmpty() {
		return
	}
	a.outputFn(a.bucket.flush())
}
