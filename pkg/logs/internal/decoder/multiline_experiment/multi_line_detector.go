// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//revive:disable
package multilineexperiment

import (
	"math"
	"sort"
	"time"

	"github.com/DataDog/datadog-agent/pkg/config"
	"github.com/DataDog/datadog-agent/pkg/logs/message"
	"github.com/DataDog/datadog-agent/pkg/util/log"
)

type tokenCluster struct {
	score  int
	tokens []Token
	sample string
}

type MultiLineDetector struct {
	enabled bool

	tokenLength         int
	tokenMatchThreshold float64
	detectionThreshold  float64
	clusterTableMaxSize int
	foundMultiLineLog   *bool
	reportTimer         *time.Timer
	model               *MarkovChain

	clusterTable []*tokenCluster
}

func NewMultiLineDetector() *MultiLineDetector {

	enabled := config.Datadog.GetBool("logs_config.multi_line_experiment.enabled")
	tokenLength := config.Datadog.GetInt("logs_config.multi_line_experiment.token_length")
	tokenMatchThreshold := config.Datadog.GetFloat64("logs_config.multi_line_experiment.token_match_threshold")
	detectionThreshold := config.Datadog.GetFloat64("logs_config.multi_line_experiment.detection_threshold")
	clusterTableMaxSize := config.Datadog.GetInt("logs_config.multi_line_experiment.cluster_table_max_size")
	reportInterval := config.Datadog.GetDuration("logs_config.multi_line_experiment.report_interval")

	var model *MarkovChain
	if enabled {
		model = compileModel(tokenLength)
	}

	return &MultiLineDetector{
		enabled:             enabled,
		tokenLength:         tokenLength,
		tokenMatchThreshold: tokenMatchThreshold,
		detectionThreshold:  detectionThreshold,
		clusterTableMaxSize: clusterTableMaxSize,
		reportTimer:         time.NewTimer(reportInterval),
		model:               model,
		clusterTable:        []*tokenCluster{},
	}
}

func (m *MultiLineDetector) processMesage(message *message.Message) {

	if !m.enabled {
		return
	}

	content := message.GetContent()

	if len(content) <= 0 {
		return
	}

	// 1. Tokenize the log
	maxLength := len(content)
	if maxLength > m.tokenLength {
		maxLength = m.tokenLength
	}
	sample := content[:maxLength]
	tokens := tokenize(sample, m.tokenLength)

	// 2. Check if we already have a cluster matching these tokens
	matched := false
	for i, cluster := range m.clusterTable {
		matched = isMatch(tokens, cluster.tokens, m.tokenMatchThreshold)
		if matched {
			cluster.score++

			// By keeping the scored clusters sorted, the best match always comes first. Since we expect one timestamp to match overwhelmingly
			// it should match most often causing few re-sorts.
			if i != 0 {
				sort.Slice(m.clusterTable, func(i, j int) bool {
					return m.clusterTable[i].score > m.clusterTable[j].score
				})
			}
			break
		}
	}

	// 3. If no match is found, classify the log as a timestamp or not
	if !matched && len(m.clusterTable) < m.clusterTableMaxSize {
		score := m.model.TestFit(tokens)
		log.Debug("Multiline tested with score ", score, string(sample))
		if score > m.detectionThreshold {
			m.clusterTable = append(m.clusterTable, &tokenCluster{
				score:  1,
				tokens: tokens,
				sample: string(sample),
			})
		}
	}

	// To prevent the cluster table from growing indefinitely drop new clusters when we reach the max.
	// In the future we can implement resizeing and eviction strategies.
	if matched && len(m.clusterTable) >= m.clusterTableMaxSize {
		log.Warn("MULTI_LINE_EXPERIMENT: Multiline detector is full, dropping new cluster. Max size is ", m.clusterTableMaxSize)
	}
}

func (m *MultiLineDetector) FoundMultiLineLog(val bool) {
	if !m.enabled {
		return
	}

	m.foundMultiLineLog = &val
	m.ReportAnalytics(true)
}

func (m *MultiLineDetector) ReportAnalytics(force bool) {
	// Don't report analytics if disable, or until after we have finished detection.
	if !m.enabled && m.foundMultiLineLog != nil {
		return
	}

	if !force {
		// Throughput reporting
		select {
		case <-m.reportTimer.C:
			break
		default:
			return
		}
	}

	if len(m.clusterTable) <= 0 {
		return
	}

	log.Info("MULTI_LINE_EXPERIMENT: Multiline detector report")
	log.Info("MULTI_LINE_EXPERIMENT: Cluster table size ", len(m.clusterTable))
	log.Info("MULTI_LINE_EXPERIMENT: top cluster score ", m.clusterTable[0].score)

}

func aproxomatlyEqual(a float64, b float64, thresh float64) bool {
	return math.Abs(a-b) <= thresh
}

func compileModel(tokenLength int) *MarkovChain {
	model := NewMarkovChain()

	timestamps := []string{
		"2021-03-28T13:45:30.123456Z",
		"28/Mar/2021:13:45:30 -0700",
		"Sun, 28 Mar 2021 13:45:30 -0700",
		"2021-03-28 13:45:30",
		"2021-03-28 13:45:30,123",
		"02 Jan 06 15:04 MST",
		"2023-03-28T14:33:53.743350Z",
		"[28/Mar/2023:15:21:28 +0000]",
		"[2023-03-28T15:21:35.680Z]",
		"2023-03-28T15:19:38.578639+00:00",
		"2023-03-28 15:44:53",
		"2022-08-20'T'13:20:10*633+0000",
		"2022 Mar 03 05:12:41.211 PDT",
		"Jan 21 18:20:11 +0000 2022",
		"19/Apr/2022:06:36:15 -0700",
		"Dec 2, 2022 2:39:58 AM",
		"Jun 09 2022 15:28:14",
		"Apr 20 00:00:35 2010",
		"Sep 28 19:00:00 +0000",
		"Mar 16 08:12:04",
		"2022-10-14T22:11:20+0000",
		"2022-07-01T14:59:55.711'+0000'",
		"2022-07-01T14:59:55.711Z",
		"2022-08-19 12:17:55 -0400",
		"2022-08-19 12:17:55-0400",
		"2022-06-26 02:31:29,573",
		"2022/04/12*19:37:50",
		"2022 Apr 13 22:08:13.211*PDT",
		"2022 Mar 10 01:44:20.392",
		"2022-03-10 14:30:12,655+0000",
		"2022-02-27 15:35:20.311",
		"2022-03-12 13:11:34.222-0700",
		"2022-07-22'T'16:28:55.444",
		"2022-09-08'T'03:13:10",
		"2022-03-12'T'17:56:22'-0700'",
		"2022-11-22'T'10:10:15.455",
		"2022-02-11'T'18:31:44",
		"2022-10-30*02:47:33:899",
		"2022-07-04*13:23:55",
		"22-02-11 16:47:35,985 +0000",
		"22-06-26 02:31:29,573",
		"22-04-19 12:00:17",
		"06/01/22 04:11:05",
		"220423 11:42:35",
		"20220423 11:42:35.173",
		"08/10/22*13:33:56",
		"11/22/2022*05:13:11",
		"05/09/2022*08:22:14*612",
		"04/23/22 04:34:22 +0000",
		"10/03/2022 07:29:46 -0700",
		"11:42:35",
		"11:42:35.173",
		"11:42:35,173",
		"23/Apr 11:42:35,173",
		"23/Apr/2022:11:42:35",
		"23/Apr/2022 11:42:35",
		"23-Apr-2022 11:42:35",
		"23-Apr-2022 11:42:35.883",
		"23 Apr 2022 11:42:35",
		"23 Apr 2022 10:32:35*311",
		"0423_11:42:35",
		"0423_11:42:35.883",
		"8/5/2022 3:31:18 AM:234",
		"9/28/2022 2:23:15 PM",
	}

	for _, str := range timestamps {
		model.Add(tokenize([]byte(str), tokenLength))
	}
	model.Compile()
	return model
}
