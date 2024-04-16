// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//revive:disable
package multilineexperiment

import (
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
	reportInterval      time.Duration
	reportTicker        *time.Ticker

	clusterTable []*tokenCluster
}

func NewMultiLineDetector() *MultiLineDetector {

	enabled := config.Datadog.GetBool("logs_config.multi_line_experiment.enabled")
	tokenLength := config.Datadog.GetInt("logs_config.multi_line_experiment.token_length")
	tokenMatchThreshold := config.Datadog.GetFloat64("logs_config.multi_line_experiment.token_match_threshold")
	detectionThreshold := config.Datadog.GetFloat64("logs_config.multi_line_experiment.detection_threshold")
	clusterTableMaxSize := config.Datadog.GetInt("logs_config.multi_line_experiment.cluster_table_max_size")
	reportInterval := config.Datadog.GetDuration("logs_config.multi_line_experiment.report_interval")

	return &MultiLineDetector{
		enabled:             enabled,
		tokenLength:         tokenLength,
		tokenMatchThreshold: tokenMatchThreshold,
		detectionThreshold:  detectionThreshold,
		clusterTableMaxSize: clusterTableMaxSize,
		reportInterval:      reportInterval,
		reportTicker:        time.NewTicker(reportInterval),
		clusterTable:        []*tokenCluster{},
	}
}

func (m *MultiLineDetector) ProcessMesage(message *message.Message) {

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

	// 3. If no match is found, add to the table
	if !matched && len(m.clusterTable) < m.clusterTableMaxSize {
		m.clusterTable = append(m.clusterTable, &tokenCluster{
			score:  1,
			tokens: tokens,
			sample: string(sample),
		})
	}

	// To prevent the cluster table from growing indefinitely drop new clusters when we reach the max.
	// In the future we can implement resizeing and eviction strategies.
	if matched && len(m.clusterTable) >= m.clusterTableMaxSize {
		log.Warn("MULTI_LINE_EXPERIMENT: Multiline detector is full, dropping new cluster. Max size is ", m.clusterTableMaxSize)
	}

	m.reportAnalytics(false)
}

func (m *MultiLineDetector) FoundMultiLineLog(val bool) {
	if !m.enabled {
		return
	}

	m.foundMultiLineLog = &val
	m.reportTicker = time.NewTicker(m.reportInterval)
	m.reportAnalytics(true)
}

func (m *MultiLineDetector) reportAnalytics(force bool) {
	// Don't report analytics if disable, or until after we have finished detection.
	if !m.enabled && m.foundMultiLineLog != nil {
		return
	}

	if !force {
		// Throughput reporting
		select {
		case <-m.reportTicker.C:
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

	if len(m.clusterTable) == 1 {
		log.Info("MULTI_LINE_EXPERIMENT: Found 1 cluster, single line log.")
	}

	if len(m.clusterTable) > 1 {
		first := m.clusterTable[0].score
		second := m.clusterTable[1].score
		ratio := float64(first) / float64(first+second)

		if ratio > m.detectionThreshold {
			log.Info("MULTI_LINE_EXPERIMENT: Top cluster is ", ratio, " times more likely. - high confidence multiline log.")
		} else {
			log.Info("MULTI_LINE_EXPERIMENT: Mixed format log likely!!!")
		}
	}

	for i, cluster := range m.clusterTable {
		log.Info("MULTI_LINE_EXPERIMENT: cluster ", i, " score ", cluster.score, " sample ", cluster.sample, " tokens ", tokensToString(cluster.tokens))
	}

}
