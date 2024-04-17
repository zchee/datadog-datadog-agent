// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

// Package multilineexperiment contains the multi-line experiment code.
package multilineexperiment

import (
	"encoding/json"
	"sort"
	"time"

	"github.com/DataDog/datadog-agent/pkg/config"
	"github.com/DataDog/datadog-agent/pkg/logs/message"
	"github.com/DataDog/datadog-agent/pkg/util/log"
)

// AnalyticsPayload contains the analytics data for the multi-line experiment
type AnalyticsPayload struct {
	Clusters             int          `json:"clusters"`
	DroppedClusters      int          `json:"dropped_clusters"`
	DetectedMultiLineLog bool         `json:"detected_multi_line_log"`
	MixedFormatLikely    bool         `json:"mixed_format_likely"`
	Confidence           float64      `json:"confidence"`
	TopMatch             ClusterRow   `json:"top_match"`
	ClusterTable         []ClusterRow `json:"clusters_table"`
}

// ClusterRow represents a row in the cluster table
type ClusterRow struct {
	Score  int    `json:"score"`
	Tokens string `json:"tokens"`
	Sample string `json:"sample"`
}

type tokenCluster struct {
	score  int
	tokens []Token
	sample string
}

// MultiLineDetector is collects data about logs and reports metrics if we think they are multi-line.
type MultiLineDetector struct {
	enabled             bool
	tokenLength         int
	tokenMatchThreshold float64
	detectionThreshold  float64
	clusterTableMaxSize int
	foundMultiLineLog   *bool
	reportInterval      time.Duration
	reportTicker        *time.Ticker
	droppedClusters     int

	clusterTable []*tokenCluster
}

// NewMultiLineDetector returns a new MultiLineDetector
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
		droppedClusters:     0,
		reportTicker:        time.NewTicker(reportInterval),
		clusterTable:        []*tokenCluster{},
	}
}

// ProcessMesage processes a message and updates the cluster table
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
		m.droppedClusters++
	}

	m.reportAnalytics(false)
}

// FoundMultiLineLog reports if a multi-line log was detected from the core-agent mulit-line detection
func (m *MultiLineDetector) FoundMultiLineLog(val bool) {
	if !m.enabled {
		return
	}

	m.foundMultiLineLog = &val
	m.reportTicker = time.NewTicker(m.reportInterval)
	m.reportAnalytics(true)
}

func (m *MultiLineDetector) buildPayload() *AnalyticsPayload {
	payload := &AnalyticsPayload{
		Clusters:             len(m.clusterTable),
		DroppedClusters:      m.droppedClusters,
		DetectedMultiLineLog: *m.foundMultiLineLog,
		ClusterTable:         []ClusterRow{},
	}

	if len(m.clusterTable) >= 1 {
		payload.Confidence = 1
		payload.TopMatch = ClusterRow{
			Score:  m.clusterTable[0].score,
			Tokens: tokensToString(m.clusterTable[0].tokens),
			Sample: m.clusterTable[0].sample,
		}
	}

	if len(m.clusterTable) > 1 {
		first := m.clusterTable[0].score
		second := m.clusterTable[1].score
		confidence := float64(first) / float64(first+second)
		payload.Confidence = confidence
		payload.MixedFormatLikely = confidence <= m.detectionThreshold
	}

	for _, cluster := range m.clusterTable {
		payload.ClusterTable = append(payload.ClusterTable, ClusterRow{
			Score:  cluster.score,
			Tokens: tokensToString(cluster.tokens),
			Sample: cluster.sample,
		})
	}

	return payload

}

func (m *MultiLineDetector) reportAnalytics(force bool) {
	// Don't report analytics if disable, or until after we have finished detection.
	if !m.enabled || m.foundMultiLineLog == nil {
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

	payload := m.buildPayload()
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return
	}
	log.Infof("MULTI_LINE_EXPERIMENT: payload: %v", string(payloadBytes))
}
