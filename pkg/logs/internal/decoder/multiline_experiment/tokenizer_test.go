// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package multilineexperiment

import (
	"testing"

	"gotest.tools/assert"
)

type testCase struct {
	input         string
	expectedToken string
}

func TestTokenizer(t *testing.T) {
	testCases := []testCase{
		{input: "a", expectedToken: "C"},
		{input: "0", expectedToken: "D"},
		{input: "abcd", expectedToken: "CCCC"},
		{input: "1234", expectedToken: "DDDD"},
		{input: "abc123", expectedToken: "CCCDDD"},
		{input: "!@#$%^&*()_+[]", expectedToken: "CCCCCCC*()C+[]"},
		{input: "123-abc-[foo] (bar)", expectedToken: "DDD-CCC-[CCC] (CCC)"},
	}

	for _, tc := range testCases {
		actualToken := tokensToString(tokenize([]byte(tc.input), 100))
		assert.Equal(t, tc.expectedToken, actualToken)
	}
}
