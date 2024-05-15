// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package decoder

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/DataDog/datadog-agent/pkg/logs/message"
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
		{input: "!@#$%^&*()_+[]:-/\\.,\\'{}", expectedToken: "CCCCCCC*()C+[]:-/\\.,\\'{}"},
		{input: "123-abc-[foo] (bar)", expectedToken: "DDD-CCC-[CCC] (CCC)"},
		{input: "Sun Mar 2PM", expectedToken: "DAY MTH DPM"},
	}

	for _, tc := range testCases {
		actualToken := tokensToString(tokenize([]byte(tc.input), 100))
		assert.Equal(t, tc.expectedToken, actualToken)
	}
}

// func TestTrimStateSet(t *testing.T) {

// 	newv := trimStateSet([]float64{0, 0, 0, 0.1, 0.2, 0.3, 0.4, 0, 0, 0, 0})
// 	assert.Equal(t, []float64{0.1, 0.2, 0.3, 0.4}, newv)
// }

func TestModel(t *testing.T) {

	detector := NewMultiLineDetector(func(m *message.Message) {}, 1000)

	test := func(input string) {
		p := detector.timestampModel.MatchProbability(tokenize([]byte(input), 40))
		fmt.Printf("%.2f\t\t\t\t%v\n", p, input)
		// assert.Greater(t, p, 0.5)
	}
	p := detector.timestampModel.MatchProbability(tokenize([]byte("  File \"//./main.py\", line 20, in b"), 40))
	assert.Less(t, p, 0.22)

	p = detector.timestampModel.MatchProbability(tokenize([]byte("2024-05-15 14:04:20,365 - root"), 40))
	assert.Greater(t, p, 0.7)

	test("2021-03-28 13:45:30 App started successfully")
	test(" .  a at some log")
	test("13:45:30 2021-03-28 ")
	test("abc this 13:45:30  is a log ")
	test("abc this 13 45:30  is a log ")
	test("12:30:2017 - info App started successfully")
	test("12:30:20 - info App started successfully")
	test("2023-03.28T14-33:53-7430Z App started successfully")
	test(" [java] 1234-12-12")
	test("      at system.com.blah")
	test("Info - this is an info message App started successfully")
	test("2023-03-28T14:33:53.743350Z App started successfully")
	test("2023-03-27 12:34:56 INFO App started successfully")
	test("[2023-03-27 12:34:56] [INFO] App started successfully")
	test("[INFO] App started successfully")
	test("[INFO] test.swift:123 App started successfully")
	test("ERROR in | myFile.go:53:123 App started successfully")
	test("9/28/2022 2:23:15 PM")

}
