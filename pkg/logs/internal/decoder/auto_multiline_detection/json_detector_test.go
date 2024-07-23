// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

// Package automultilinedetection contains auto multiline detection and aggregation logic.
package automultilinedetection

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestJsonDetector(t *testing.T) {
	jsonDetector := NewJSONDetector()
	testCases := []struct {
		rawMessage    []byte
		expectedLabel Label
	}{
		{[]byte(`{"key": "value"}`), noAggregate},
		{[]byte(`             {"key": "value"}`), noAggregate},
		{[]byte(`    { "key": "value"}`), noAggregate},
		{[]byte(`    {."key": "value"}`), aggregate},
		{[]byte(`.{"key": "value"}`), aggregate},
		{[]byte(`{"another_key": "another_value"}`), noAggregate},
		{[]byte(`{"key": 12345}`), noAggregate},
		{[]byte(`{"array": [1,2,3]}`), noAggregate},
		{[]byte(`not json`), aggregate},
		{[]byte(`{foo}`), aggregate},
		{[]byte(`{bar"}`), aggregate},
		{[]byte(`"FOO"}`), aggregate},
	}

	for _, tc := range testCases {
		t.Run(string(tc.rawMessage), func(t *testing.T) {
			messageContext := &messageContext{
				rawMessage: tc.rawMessage,
				label:      aggregate,
			}
			jsonDetector.Process(messageContext)
			assert.Equal(t, tc.expectedLabel, messageContext.label)
		})
	}
}
