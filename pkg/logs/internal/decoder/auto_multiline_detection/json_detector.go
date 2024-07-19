// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

// Package automultilinedetection contains auto multiline detection and aggregation logic.
package automultilinedetection

import "regexp"

var jsonRegexp = regexp.MustCompile(`^\s*\{\s*\"`)

type jsonDetector struct{}

// NewJSONDetector returns a new JSON detection heuristic.
func NewJSONDetector() *jsonDetector {
	return &jsonDetector{}
}

// Process checks if a message is a JSON message.
func (j *jsonDetector) Process(context *messageContext) bool {
	if jsonRegexp.Match(context.rawMessage) {
		context.label = noAggregate
		return false
	}
	return true
}
