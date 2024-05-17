// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package decoder

import (
	"fmt"
	"regexp"
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
		{input: "!@#$%^&*()_+[]:-/\\.,\\'{}", expectedToken: "CCCCCCC*()_+[]:-/\\.,\\'{}"},
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
		if len(input) > 40 {
			input = input[:40]
		}
		// fmt.Println(tokensToString(tokenize([]byte(input), 40)))
		p := detector.timestampModel.MatchProbability(tokenize([]byte(input), 40))
		fmt.Printf("%.2f\t\t\t\t%v\n", p, input)
		// assert.Greater(t, p, 0.5)
	}
	p := detector.timestampModel.MatchProbability(tokenize([]byte("  File \"//./main.py\", line 20, in b"), 40))
	assert.Less(t, p, 0.22)

	// fmt.Println(tokensToString(tokenize([]byte("  File \"//./main.py\", line 20, in b"), 40)))

	// p = detector.timestampModel.MatchProbability(tokenize([]byte("2024-05-15 14:04:20,365 - root"), 40))
	// assert.Greater(t, p, 0.7)

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
	test("2024-05-15 17:04:12,369 - root - DEBUG -")
	test("[2024-05-15T18:03:23.501Z] Info : All routes applied.")
	test("2024-05-15 14:03:13 EDT | CORE | INFO | (pkg/logs/tailers/file/tailer.go:353 in forwardMessages) | ")
	test("20171223-22:15:29:606|Step_LSC|30002312|onStandStepChanged 3579")
	test("Jun 14 15:16:01 combo sshd(pam_unix)[19939]: authentication failure; logname= uid=0 euid=0 tty=NODEVssh ruser= rhost=218.188.2.4 ")
	test("Jul  1 09:00:55 calvisitor-10-105-160-95 kernel[0]: IOThunderboltSwitch<0>(0x0)::listenerCallback -")
	test("nova-api.log.1.2017-05-16_13:53:08 2017-05-16 00:00:00.008 25746 INFO nova.osapi")
	test("54fadb412c4e40cdbaed9335e4c35a9e - - -] 10.11.10.1 ")
	test("[Sun Dec 04 04:47:44 2005] [notice] workerEnv.init() ok /etc/httpd/conf/workers2.properties")
	test("2024/05/16 14:47:42 Datadog Tracer v1.64")
	test("2024/05/16 19:46:15 Datadog Tracer v1.64.0-rc.1 ")
	test("127.0.0.1 - - [16/May/2024:19:49:17 +0000]")
	test("127.0.0.1 - - [17/May/2024:13:51:52 +0000] \"GET /probe?debug=1 HTTP/1.1\" 200 0	")
	test("'/conf.d/..data/container_lifecycle.yaml' ")
	test("commit: 04a34f1e96d7eb8795b0f944b1ea388281990fc8")
	test(" auth.handler: auth handler stopped")
}

var testData = []string{
	"2021-03-28 13:45:30 App started successfully",
	" .  a at some log",
	"13:45:30 2021-03-28 ",
	"abc this 13:45:30  is a log ",
	"abc this 13 45:30  is a log ",
	"12:30:2017 - info App started successfully",
	"12:30:20 - info App started successfully",
	"2023-03.28T14-33:53-7430Z App started successfully",
	" [java] 1234-12-12",
	"      at system.com.blah",
	"Info - this is an info message App started successfully",
	"2023-03-28T14:33:53.743350Z App started successfully",
	"2023-03-27 12:34:56 INFO App started successfully",
	"[2023-03-27 12:34:56] [INFO] App started successfully",
	"[INFO] App started successfully",
	"[INFO] test.swift:123 App started successfully",
	"ERROR in | myFile.go:53:123 App started successfully",
	"9/28/2022 2:23:15 PM",
	"2024-05-15 17:04:12,369 - root - DEBUG -",
	"[2024-05-15T18:03:23.501Z] Info : All routes applied.",
	"2024-05-15 14:03:13 EDT | CORE | INFO | (pkg/logs/tailers/file/tailer.go:353 in forwardMessages) | ",
	"20171223-22:15:29:606|Step_LSC|30002312|onStandStepChanged 3579",
	"Jun 14 15:16:01 combo sshd(pam_unix)[19939]: authentication failure; logname= uid=0 euid=0 tty=NODEVssh ruser= rhost=218.188.2.4 ",
	"Jul  1 09:00:55 calvisitor-10-105-160-95 kernel[0]: IOThunderboltSwitch<0>(0x0)::listenerCallback -",
	"nova-api.log.1.2017-05-16_13:53:08 2017-05-16 00:00:00.008 25746 INFO nova.osapi",
	"54fadb412c4e40cdbaed9335e4c35a9e - - -] 10.11.10.1 ",
	"[Sun Dec 04 04:47:44 2005] [notice] workerEnv.init() ok /etc/httpd/conf/workers2.properties",
	"2024/05/16 14:47:42 Datadog Tracer v1.64",
	"2024/05/16 19:46:15 Datadog Tracer v1.64.0-rc.1 ",
	"127.0.0.1 - - [16/May/2024:19:49:17 +0000]",
	"'/conf.d/..data/container_lifecycle.yaml' ",
	"commit: 04a34f1e96d7eb8795b0f944b1ea388281990fc8",
}

func BenchmarkTest1(b *testing.B) {
	// make sure to prepend it with `^`
	formatsToTry := []*regexp.Regexp{
		// time.RFC3339,
		regexp.MustCompile(`^\d+-\d+-\d+T\d+:\d+:\d+(\.\d+)?(Z\d*:?\d*)?`),
		regexp.MustCompile(`^[A-Za-z_]+ [A-Za-z_]+ +\d+ \d+:\d+:\d+ \d+`),
		regexp.MustCompile(`^[A-Za-z_]+ [A-Za-z_]+ +\d+ \d+:\d+:\d+( [A-Za-z_]+ \d+)?`),
		regexp.MustCompile(`^[A-Za-z_]+ [A-Za-z_]+ \d+ \d+:\d+:\d+ [\-\+]\d+ \d+`),
		regexp.MustCompile(`^\d+ [A-Za-z_]+ \d+ \d+:\d+ [A-Za-z_]+`),
		regexp.MustCompile(`^\d+ [A-Za-z_]+ \d+ \d+:\d+ -\d+`),
		regexp.MustCompile(`^[A-Za-z_]+, \d+-[A-Za-z_]+-\d+ \d+:\d+:\d+ [A-Za-z_]+`),
		regexp.MustCompile(`^[A-Za-z_]+, \d+ [A-Za-z_]+ \d+ \d+:\d+:\d+ [A-Za-z_]+`),
		regexp.MustCompile(`^[A-Za-z_]+, \d+ [A-Za-z_]+ \d+ \d+:\d+:\d+ -\d+`),
		regexp.MustCompile(`^\d+-\d+-\d+[A-Za-z_]+\d+:\d+:\d+\.\d+[A-Za-z_]+\d+:\d+`),
		regexp.MustCompile(`^\d+-\d+-\d+ \d+:\d+:\d+(,\d+)?`),
		regexp.MustCompile(`^[A-Za-z_]+ \d+, \d+ \d+:\d+:\d+ (AM|PM)`),
		regexp.MustCompile(`^\d{4}-(0?[1-9]|1[012])-(0?[1-9]|[12][0-9]|3[01])`),
	}

	b.ResetTimer()

	for n := 0; n < b.N; n++ {
		for _, s := range testData {
			for _, regex := range formatsToTry {
				regex.Match([]byte(s))
			}
		}
	}
}

func BenchmarkTest2(b *testing.B) {
	m := NewModelMatcher()

	samples := []string{
		"12-12-12T12:12:21Z12:12",
		"ab ab 1 1:1:1 1",
		"ab ab 1 1:1:1 abc 12",
		"ab ab 1 1:1:1 +2 1",
		"12 av 12 12:12 ab",
		"12 ab 12 12:12 -12",
		"ab, 12-ab-12 12:12:12 ab",
		"ab, 12 ab 12 12:12:12 ab",
		"ab, 12 ab 12 12:12:12 -1",
		"12-12-12T12:12:12.12T12:12",
		"12-12-12 12:12:12,1",
		"ab 12, 12 12:12:12 AM",
		"1234-12-21",
	}

	for _, in := range samples {
		m.Add(tokenize([]byte(in), 40))
	}
	m.Compile()

	tokenizedData := [][]Token{}
	for _, text := range testData {
		tokenizedData = append(tokenizedData, tokenize([]byte(text), 40))
	}

	b.ResetTimer()

	for n := 0; n < b.N; n++ {
		for _, s := range tokenizedData {
			m.MatchProbability(s)
		}
	}
}
