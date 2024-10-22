// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build windows

// Package msilogparser provides facilities to parse MSI logs
package msilogparser

import (
	"bufio"
	"context"
	"golang.org/x/text/encoding/unicode"
	"golang.org/x/text/transform"
	"gopkg.in/DataDog/dd-trace-go.v1/ddtrace/tracer"
	"os"
	"regexp"
	"time"
)

type MsiLogParser struct {
	actionLineRegex   *regexp.Regexp
	customActionRegex *regexp.Regexp
	spans             map[string]tracer.Span
}

func (msi *MsiLogParser) startSpan(ctx context.Context, action, start string) error {
	startTime, err := time.Parse("dd:mm:ss", start)
	if err != nil {
		return err
	}
	span, ctx := tracer.StartSpanFromContext(ctx, "action", tracer.StartTime(startTime))
	msi.spans[action] = span
	return nil
}

func (msi *MsiLogParser) finishSpan(action, end string) error {
	span := msi.spans[action]
	delete(msi.spans, action)
	endTime, err := time.Parse("dd:mm:ss", end)
	if err != nil {
		return err
	}
	span.Finish(tracer.FinishTime(endTime))
	return nil
}

func (msi *MsiLogParser) handleLine(ctx context.Context, line string) {
	matches := msi.actionLineRegex.FindStringSubmatch(line)
	if len(matches) != 0 {
		if matches[1] == "start" {
			msi.startSpan(ctx, matches[3], matches[2])
		}
		if matches[1] == "end" {
			msi.finishSpan(matches[3], matches[2])
		}
	}
	matches = msi.customActionRegex.FindStringSubmatch(line)
	if len(matches) != 0 {
		msi.startSpan(ctx, matches[3], matches[2])
		msi.finishSpan(matches[3], matches[2])
	}
}

func (msi *MsiLogParser) Parse(ctx context.Context, logPath string) error {
	file, err := os.Open(logPath)
	if err != nil {
		return err
	}
	defer file.Close()

	dec := transform.NewReader(file, unicode.UTF16(unicode.LittleEndian, unicode.ExpectBOM).NewDecoder())
	scanner := bufio.NewScanner(dec)
	for scanner.Scan() {
		msi.handleLine(ctx, scanner.Text())
	}

	if err := scanner.Err(); err != nil {
		return err
	}
	return nil
}

func NewMsiLogParser() *MsiLogParser {
	logsParser := &MsiLogParser{
		spans:             make(map[string]tracer.Span),
		actionLineRegex:   regexp.MustCompile("Action (.+) (\\d\\d:\\d\\d:\\d\\d): ([^\\.]*)\\."),
		customActionRegex: regexp.MustCompile("CA: (\\d\\d:\\d\\d:\\d\\d): ([^\\.]*)\\."),
	}
	return logsParser
}
