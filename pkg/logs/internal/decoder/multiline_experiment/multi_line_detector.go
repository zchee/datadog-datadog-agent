// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

// Package multilineexperiment contains the multi-line experiment code.
package multilineexperiment

import (
	"encoding/json"
	"regexp"
	"sort"
	"time"

	"github.com/google/uuid"

	"github.com/DataDog/datadog-agent/pkg/config"
	"github.com/DataDog/datadog-agent/pkg/logs/message"
	"github.com/DataDog/datadog-agent/pkg/util/log"
)

var jsonRegexp = regexp.MustCompile(`^\s*\{\s*\"`)

// AnalyticsPayload contains the analytics data for the multi-line experiment
type AnalyticsPayload struct {
	ID                   string       `json:"id"`
	Clusters             int          `json:"clusters"`
	Samples              int          `json:"samples"`
	DroppedClusters      int          `json:"dropped_clusters"`
	DetectedMultiLineLog bool         `json:"detected_multi_line_log"`
	MixedFormatLikely    bool         `json:"mixed_format_likely"`
	IsJSON               bool         `json:"is_json"`
	Confidence           float32      `json:"confidence"`
	TopMatch             ClusterRow   `json:"top_match"`
	ClusterTable         []ClusterRow `json:"clusters_table"`
}

// ClusterRow represents a row in the cluster table
type ClusterRow struct {
	Score       int64   `json:"score"`
	Weight      float32 `json:"weight"`
	SampleCount int64   `json:"sample_count"`
	Tokens      string  `json:"tokens"`
	Sample      string  `json:"sample"`
}

type tokenCluster struct {
	score                float64
	sampleCount          int64
	weight               float64
	timestampProbability float32
	tokens               []Token
	sample               string
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
	totalSamples        int
	containsJSON        bool
	id                  string
	timestampModel      *MarkovChain

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
		totalSamples:        0,
		containsJSON:        false,
		id:                  uuid.New().String(),
		reportTicker:        time.NewTicker(reportInterval),
		clusterTable:        []*tokenCluster{},
		timestampModel:      compileModel(tokenLength),
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

	defer m.reportAnalytics(false)

	m.totalSamples++
	isJSONLog := false

	// 1. pre-process: if log is json, never aggregate
	if jsonRegexp.Match(content) {
		m.containsJSON = true
		isJSONLog = true
	}

	// 2. Tokenize the log
	maxLength := len(content)
	if maxLength > m.tokenLength {
		maxLength = m.tokenLength
	}
	sample := content[:maxLength]
	tokens := tokenize(sample, m.tokenLength)

	// 3. Check if we already have a cluster matching these tokens
	matched := false
	for i, cluster := range m.clusterTable {
		matched = isMatch(tokens, cluster.tokens, m.tokenMatchThreshold)
		if matched {
			cluster.sampleCount++
			cluster.score += (1 * cluster.weight)

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

	// 4. If no match is found, add to the table
	if !matched && len(m.clusterTable) < m.clusterTableMaxSize {
		var weight float64
		p := float64(0)

		// 5. Compute weight.
		if isJSONLog {
			// If log is Json, down-weight it.
			weight = 0.001
		} else {
			// Compute probability that log starts with a timestamp to determine it's weight
			p = m.timestampModel.MatchProbability(tokens)
			weight = 10 * p
		}

		m.clusterTable = append(m.clusterTable, &tokenCluster{
			score:                1,
			sampleCount:          1,
			weight:               weight,
			timestampProbability: float32(p),
			tokens:               tokens,
			sample:               string(sample),
		})
	}

	// To prevent the cluster table from growing indefinitely drop new clusters when we reach the max.
	// In the future we can implement resizeing and eviction strategies.
	if matched && len(m.clusterTable) >= m.clusterTableMaxSize {
		m.droppedClusters++
	}

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
		ID:                   m.id,
		Clusters:             len(m.clusterTable),
		DroppedClusters:      m.droppedClusters,
		DetectedMultiLineLog: *m.foundMultiLineLog,
		ClusterTable:         []ClusterRow{},
		Samples:              m.totalSamples,
		IsJSON:               m.containsJSON,
	}

	if len(m.clusterTable) >= 1 {
		payload.Confidence = 1
		payload.TopMatch = ClusterRow{
			Score:       int64(m.clusterTable[0].score),
			Weight:      float32(m.clusterTable[0].weight),
			Tokens:      tokensToString(m.clusterTable[0].tokens),
			Sample:      m.clusterTable[0].sample,
			SampleCount: m.clusterTable[0].sampleCount,
		}
	}

	// Compute confidence
	if len(m.clusterTable) > 1 {
		score := m.clusterTable[0].score
		count := float64(m.clusterTable[0].sampleCount)

		confidence := score / count
		payload.Confidence = float32(confidence)
	}

	// Compute mixed format likely
	if len(m.clusterTable) > 1 {

		sampleTable := make([]*tokenCluster, len(m.clusterTable))
		_ = copy(sampleTable, m.clusterTable)
		sort.Slice(sampleTable, func(i, j int) bool {
			return float64(sampleTable[i].sampleCount) > float64(sampleTable[j].sampleCount)
		})

		first := sampleTable[0].sampleCount
		second := sampleTable[1].sampleCount
		confidence := float64(first) / float64(first+second)
		payload.MixedFormatLikely = confidence <= m.detectionThreshold
	}

	for _, cluster := range m.clusterTable {
		payload.ClusterTable = append(payload.ClusterTable, ClusterRow{
			Score:       int64(cluster.score),
			Weight:      float32(cluster.weight),
			Tokens:      tokensToString(cluster.tokens),
			Sample:      cluster.sample,
			SampleCount: cluster.sampleCount,
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

func compileModel(tokenLength int) *MarkovChain {
	model := NewMarkovChain()

	timestamps := []string{
		"2024-03-28T13:45:30.123456Z",
		"28/Mar/2024:13:45:30 -0700",
		"Sun, 28 Mar 2024 13:45:30 -0700",
		"2024-03-28 13:45:30",
		"2024-03-28 13:45:30,123",
		"02 Jan 06 15:04 MST",
		"2024-03-28T14:33:53.743350Z",
		"[28/Mar/2024:15:21:28 +0000]",
		"[2024-03-28T15:21:35.680Z]",
		"2024-03-28T15:19:38.578639+00:00",
		"2024-03-28 15:44:53",
		"2024-08-20'T'13:20:10*633+0000",
		"2024 Mar 03 05:12:41.211 PDT",
		"Jan 21 18:20:11 +0000 2024",
		"19/Apr/2024:06:36:15 -0700",
		"Dec 2, 2024 2:39:58 AM",
		"Jun 09 2024 15:28:14",
		"Apr 20 00:00:35 2010",
		"Sep 28 19:00:00 +0000",
		"Mar 16 08:12:04",
		"2024-10-14T22:11:20+0000",
		"2024-07-01T14:59:55.711'+0000'",
		"2024-07-01T14:59:55.711Z",
		"2024-08-19 12:17:55 -0400",
		"2024-08-19 12:17:55-0400",
		"2024-06-26 02:31:29,573",
		"2024/04/12*19:37:50",
		"2024 Apr 13 22:08:13.211*PDT",
		"2024 Mar 10 01:44:20.392",
		"2024-03-10 14:30:12,655+0000",
		"2024-02-27 15:35:20.311",
		"2024-03-12 13:11:34.222-0700",
		"2024-07-22'T'16:28:55.444",
		"2024-09-08'T'03:13:10",
		"2024-03-12'T'17:56:22'-0700'",
		"2024-11-22'T'10:10:15.455",
		"2024-02-11'T'18:31:44",
		"2024-10-30*02:47:33:899",
		"2024-07-04*13:23:55",
		"24-02-11 16:47:35,985 +0000",
		"24-06-26 02:31:29,573",
		"24-04-19 12:00:17",
		"06/01/24 04:11:05",
		"220423 11:42:35",
		"20240423 11:42:35.173",
		"08/10/24*13:33:56",
		"11/24/2024*05:13:11",
		"05/09/2024*08:22:14*612",
		"04/23/24 04:34:22 +0000",
		"10/03/2024 07:29:46 -0700",
		"11:42:35",
		"11:42:35.173",
		"11:42:35,173",
		"23/Apr 11:42:35,173",
		"23/Apr/2024:11:42:35",
		"23/Apr/2024 11:42:35",
		"23-Apr-2024 11:42:35",
		"23-Apr-2024 11:42:35.883",
		"23 Apr 2024 11:42:35",
		"23 Apr 2024 10:32:35*311",
		"0423_11:42:35",
		"0423_11:42:35.883",
		"8/5/2024 3:31:18 AM:234",
		"9/28/2024 2:23:15 PM",
	}

	for _, str := range timestamps {
		model.Add(tokenize([]byte(str), tokenLength))
	}
	model.Compile()
	return model
}
