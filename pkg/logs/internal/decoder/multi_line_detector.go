// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

// Package decoder contains the multi-line experiment code.
package decoder

import (
	"bytes"
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
	ID              string `json:"id"`
	Clusters        int    `json:"clusters"`
	Samples         int    `json:"samples"`
	DroppedClusters int    `json:"dropped_clusters"`
	// DetectedMultiLineLog bool         `json:"detected_multi_line_log"`
	// MixedFormatLikely    bool         `json:"mixed_format_likely"`
	// IsJSON               bool         `json:"is_json"`
	// Confidence           float32      `json:"confidence"`
	TopMatch     ClusterRow   `json:"top_match"`
	ClusterTable []ClusterRow `json:"clusters_table"`
}

// ClusterRow represents a row in the cluster table
type ClusterRow struct {
	// Score       int64   `json:"score"`
	TimestampMatch float32 `json:"timestampMatch"`
	SampleCount    int64   `json:"sample_count"`
	Tokens         string  `json:"tokens"`
	Sample         string  `json:"sample"`
	Label          string  `json:"label"`
	MatchedRegex   bool    `json:"matched_regex"`
}

type tokenCluster struct {
	// score                float64
	sampleCount          int64
	timestampMatch       float64
	timestampProbability float32
	tokens               []Token
	sample               string
	label                label
	matchedRegex         bool
}

// MultiLineDetector is collects data about logs and reports metrics if we think they are multi-line.
type MultiLineDetector struct {
	Enabled             bool
	tokenLength         int
	tokenMatchThreshold float64
	detectionThreshold  float64
	clusterTableMaxSize int
	// foundMultiLineLog       *bool
	reportInterval          time.Duration
	reportTicker            *time.Ticker
	droppedClusters         int
	totalSamples            int
	containsJSON            bool
	id                      string
	timestampModel          ModelMatcher
	clusterTable            []*tokenCluster
	outputFn                func(*message.Message)
	buffer                  *bytes.Buffer
	shouldTruncate          bool
	lineCount               int
	status                  string
	timestamp               string
	lineLimit               int
	sampleThreshold         int64
	timestampMatchThreshold float64
}

type label uint32

const (
	startGroup label = iota
	noAggregate
	aggregate
)

// NewMultiLineDetector returns a new MultiLineDetector
func NewMultiLineDetector(outputFn func(*message.Message), lineLimit int) *MultiLineDetector {
	enabled := config.Datadog.GetBool("logs_config.multi_line_experiment.enabled")
	tokenLength := config.Datadog.GetInt("logs_config.multi_line_experiment.token_length")
	tokenMatchThreshold := config.Datadog.GetFloat64("logs_config.multi_line_experiment.token_match_threshold")
	detectionThreshold := config.Datadog.GetFloat64("logs_config.multi_line_experiment.detection_threshold")
	clusterTableMaxSize := config.Datadog.GetInt("logs_config.multi_line_experiment.cluster_table_max_size")
	reportInterval := config.Datadog.GetDuration("logs_config.multi_line_experiment.report_interval")

	sampleThreshold := config.Datadog.GetInt64("logs_config.multi_line_experiment.sample_threshold")
	timestampMatchThreshold := config.Datadog.GetFloat64("logs_config.multi_line_experiment.timestampMatch_threshold")

	return &MultiLineDetector{
		Enabled:                 enabled,
		tokenLength:             tokenLength,
		tokenMatchThreshold:     tokenMatchThreshold,
		detectionThreshold:      detectionThreshold,
		clusterTableMaxSize:     clusterTableMaxSize,
		reportInterval:          reportInterval,
		droppedClusters:         0,
		totalSamples:            0,
		containsJSON:            false,
		id:                      uuid.New().String(),
		reportTicker:            time.NewTicker(reportInterval),
		clusterTable:            []*tokenCluster{},
		timestampModel:          compileModel(tokenLength),
		outputFn:                outputFn,
		buffer:                  bytes.NewBuffer(nil),
		shouldTruncate:          false,
		lineCount:               0,
		status:                  "",
		timestamp:               "",
		lineLimit:               lineLimit,
		sampleThreshold:         sampleThreshold,
		timestampMatchThreshold: timestampMatchThreshold,
	}
}

func (m *MultiLineDetector) sendBuffer() {
	defer func() {
		m.buffer.Reset()
		m.shouldTruncate = false
		m.lineCount = 0
	}()

	data := bytes.TrimSpace(m.buffer.Bytes())
	content := make([]byte, len(data))
	copy(content, data)

	if len(content) > 0 || m.lineCount > 0 {
		if m.lineCount > 1 {
			m.outputFn(NewMultiLineMessage(content, m.status, m.lineCount, m.timestamp))
		} else {
			m.outputFn(NewMessage(content, m.status, m.lineCount, m.timestamp))
		}
	}
}

func (m *MultiLineDetector) aggregate(message *message.Message, l label) {
	if l == noAggregate {
		m.sendBuffer()
		m.outputFn(message)
		return
	}

	if l == startGroup {
		if m.buffer.Len() > 0 {
			m.sendBuffer()
		}
	}

	if l == aggregate && m.buffer.Len() == 0 {
		// If no group has been started - don't aggregate
		m.outputFn(message)
		return
	}

	isTruncated := m.shouldTruncate
	m.shouldTruncate = false

	// track the raw data length and the timestamp so that the agent tails
	// from the right place at restart
	m.lineCount++
	m.timestamp = message.ParsingExtra.Timestamp
	m.status = message.Status

	if m.buffer.Len() > 0 {
		// the buffer already contains some data which means that
		// the current line is not the first line of the message
		m.buffer.Write(escapedLineFeed)
	}

	if isTruncated {
		// the previous line has been truncated because it was too long,
		// the new line is just a remainder,
		// adding the truncated flag at the beginning of the content
		m.buffer.Write(truncatedFlag)
	}

	m.buffer.Write(message.GetContent())

	if m.buffer.Len() >= m.lineLimit {
		// the multiline message is too long, it needs to be cut off and send,
		// adding the truncated flag the end of the content
		m.buffer.Write(truncatedFlag)
		m.sendBuffer()
		m.shouldTruncate = true
	}
}

// ProcessMesage processes a message and updates the cluster table
func (m *MultiLineDetector) ProcessMesage(message *message.Message) {
	content := message.GetContent()
	label := aggregate

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
		label = noAggregate
	}

	// 2. Tokenize the log
	maxLength := len(content)
	if maxLength > m.tokenLength {
		maxLength = m.tokenLength
	}
	sample := content[:maxLength]
	tokens := tokenize(sample, m.tokenLength)

	var timestampMatch float64

	// 3. Check if we already have a cluster matching these tokens
	matched := false
	for i, cluster := range m.clusterTable {
		matched = isMatch(tokens, cluster.tokens, m.tokenMatchThreshold)
		if matched {
			cluster.sampleCount++
			label = cluster.label

			// if the most popular log is set to be aggreagted, than it's probably NOT a multi-line log. Lets skip it.
			if i == 0 && label == aggregate {
				label = noAggregate
			}

			if i != 0 {
				sort.Slice(m.clusterTable, func(i, j int) bool {
					return m.clusterTable[i].sampleCount > m.clusterTable[j].sampleCount
				})
			}
			break
		}
	}
	matchedRegex := false

	// 4. If no match is found, add to the table
	if !matched && len(m.clusterTable) < m.clusterTableMaxSize {
		p := float64(0)

		for _, pattern := range formatsToTry {
			if pattern.Match(content) {
				matchedRegex = true
			}
		}

		// 5. Compute timestampMatch.
		if !isJSONLog {
			// Compute probability that log starts with a timestamp to determine it's timestampMatch
			p = m.timestampModel.MatchProbability(tokens)
			if p > m.timestampMatchThreshold {
				label = startGroup
			}
			timestampMatch = p
		}

		m.clusterTable = append(m.clusterTable, &tokenCluster{
			sampleCount:          1,
			timestampProbability: float32(p),
			tokens:               tokens,
			sample:               string(sample),
			timestampMatch:       timestampMatch,
			label:                label,
			matchedRegex:         matchedRegex,
		})
	}

	// To prevent the cluster table from growing indefinitely drop new clusters when we reach the max.
	// In the future we can implement resizeing and eviction strategies.
	if matched && len(m.clusterTable) >= m.clusterTableMaxSize {
		m.droppedClusters++
	}

	m.aggregate(message, label)
}

// FoundMultiLineLog reports if a multi-line log was detected from the core-agent mulit-line detection
func (m *MultiLineDetector) FoundMultiLineLog(_ bool) {
	// if !m.Enabled {
	// 	return
	// }

	// m.foundMultiLineLog = &val
	// m.reportTicker = time.NewTicker(m.reportInterval)
	// m.reportAnalytics(true)
}

func labelString(l label) string {
	labelString := "Aggregate"
	if l == startGroup {
		labelString = "StartGroup"
	} else if l == noAggregate {
		labelString = "NoAggregate"
	}
	return labelString
}

func (m *MultiLineDetector) buildPayload() *AnalyticsPayload {
	payload := &AnalyticsPayload{
		ID:              m.id,
		Clusters:        len(m.clusterTable),
		DroppedClusters: m.droppedClusters,
		// DetectedMultiLineLog: *m.foundMultiLineLog,
		ClusterTable: []ClusterRow{},
		Samples:      m.totalSamples,
		// IsJSON:               m.containsJSON,
	}

	if len(m.clusterTable) >= 1 {
		payload.TopMatch = ClusterRow{
			// Score:       int64(m.clusterTable[0].score),
			TimestampMatch: float32(m.clusterTable[0].timestampMatch),
			Tokens:         tokensToString(m.clusterTable[0].tokens),
			Sample:         m.clusterTable[0].sample,
			SampleCount:    m.clusterTable[0].sampleCount,
			Label:          labelString(m.clusterTable[0].label),
			MatchedRegex:   m.clusterTable[0].matchedRegex,
		}
	}

	// Compute mixed format likely
	if len(m.clusterTable) > 1 {

		sampleTable := make([]*tokenCluster, len(m.clusterTable))
		_ = copy(sampleTable, m.clusterTable)
		sort.Slice(sampleTable, func(i, j int) bool {
			return float64(sampleTable[i].sampleCount) > float64(sampleTable[j].sampleCount)
		})

		// first := sampleTable[0].sampleCount
		// second := sampleTable[1].sampleCount
		// confidence := float64(first) / float64(first+second)
		// payload.MixedFormatLikely = confidence <= m.detectionThreshold
	}

	for _, cluster := range m.clusterTable {
		payload.ClusterTable = append(payload.ClusterTable, ClusterRow{
			// Score:          int64(cluster.score),
			TimestampMatch: float32(cluster.timestampMatch),
			Tokens:         tokensToString(cluster.tokens),
			Sample:         cluster.sample,
			SampleCount:    cluster.sampleCount,
			Label:          labelString(cluster.label),
			MatchedRegex:   cluster.matchedRegex,
		})
	}

	return payload
}

func (m *MultiLineDetector) reportAnalytics(force bool) {
	// Don't report analytics if disable, or until after we have finished detection.
	if !m.Enabled {
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

func compileModel(tokenLength int) ModelMatcher {
	model := NewTrie()

	timestamps := []string{
		"2024-03-28T13:45:30.123456Z",
		"28/Mar/2024:13:45:30",
		"Sun, 28 Mar 2024 13:45:30",
		"2024-03-28 13:45:30",
		"2024-03-28 13:45:30,123",
		"02 Jan 06 15:04 MST",
		"2024-03-28T14:33:53.743350Z",
		"2024-03-28T15:19:38.578639+00:00",
		"2024-03-28 15:44:53",
		"2024-08-20'T'13:20:10*633+0000",
		"2024 Mar 03 05:12:41.211 PDT",
		"Jan 21 18:20:11 +0000 2024",
		"19/Apr/2024:06:36:15",
		"Dec 2, 2024 2:39:58 AM",
		"Jun 09 2024 15:28:14",
		"Apr 20 00:00:35 2010",
		"Sep 28 19:00:00 +0000",
		"Mar 16 08:12:04",
		"Jul 1 09:00:55",
		"2024-10-14T22:11:20+0000",
		"2024-07-01T14:59:55.711'+0000'",
		"2024-07-01T14:59:55.711Z",
		"2024-08-19 12:17:55",
		"2024-08-19 12:17:55-0400",
		"2024-06-26 02:31:29,573",
		"2024/04/12*19:37:50",
		"2024 Apr 13 22:08:13.211*PDT",
		"2024 Mar 10 01:44:20.392",
		"2024-03-10 14:30:12,655+0000",
		"2024-02-27 15:35:20.311",
		"2024-07-22'T'16:28:55.444",
		"2024-09-08'T'03:13:10",
		"2024-11-22'T'10:10:15.455",
		"2024-02-11'T'18:31:44",
		"2024-10-30*02:47:33:899",
		"2024-07-04*13:23:55",
		"24-02-11 16:47:35,985 +0000",
		"24-06-26 02:31:29,573",
		"24-04-19 12:00:17",
		"06/01/24 04:11:05",
		"08/10/24*13:33:56",
		"11/24/2024*05:13:11",
		"05/09/2024*08:22:14*612",
		"04/23/24 04:34:22 +0000",
		"2024/04/25 14:57:42",
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
		"8/5/2024 3:31:18 AM:234",
		"9/28/2024 2:23:15 PM",
		"2023-03.28T14-33:53-7430Z",
		"2017-05-16_13:53:08",
	}

	for _, str := range timestamps {
		model.Add(tokenize([]byte(str), tokenLength))
		// fmt.Println(tokensToString(tokenize([]byte(str), tokenLength)))
	}
	return model
}
