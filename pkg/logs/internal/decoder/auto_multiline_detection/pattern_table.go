// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

// Package automultilinedetection contains auto multiline detection and aggregation logic.
package automultilinedetection

import (
	"github.com/DataDog/datadog-agent/pkg/util/log"
)

type row struct {
	tokens    []Token
	count     int
	lastIndex int
}

// PatternTable is a table of patterns that occur over time from a log source.
type PatternTable struct {
	table          []*row
	index          int
	maxTableSize   int
	matchThreshold float64
}

// NewPatternTable returns a new PatternTable heuristic.
func NewPatternTable(maxTableSize int, matchThreshold float64) *PatternTable {
	return &PatternTable{
		table:          make([]*row, 0, 20),
		index:          0,
		maxTableSize:   maxTableSize,
		matchThreshold: matchThreshold,
	}
}

func (p *PatternTable) insert(tokens []Token) int {
	p.index++
	foundIdx := -1
	for i, r := range p.table {
		if isMatch(r.tokens, tokens, p.matchThreshold) {
			r.count++
			r.lastIndex = p.index
			foundIdx = i
			break
		}
	}

	if foundIdx > 0 {
		p.siftUp(foundIdx)
		return foundIdx
	}

	// If the table is full, make room for a new entry
	if len(p.table) >= p.maxTableSize {
		p.evictLRU()
	}

	p.table = append(p.table, &row{tokens: tokens, count: 1, lastIndex: p.index})
	return len(p.table) - 1

}

// siftUp moves the row at the given index up the table until it is in the correct position.
func (p *PatternTable) siftUp(idx int) {
	if idx == 0 {
		return
	}

	for p.table[idx].count > p.table[idx-1].count {
		p.table[idx], p.table[idx-1] = p.table[idx-1], p.table[idx]
	}
}

// evictLRU removes the least recently updated row from the table.
func (p *PatternTable) evictLRU() {
	mini := 0
	minIndex := p.index
	for i, r := range p.table {
		if r.lastIndex < minIndex {
			minIndex = r.lastIndex
			mini = i
		}
	}
	p.table = append(p.table[:mini], p.table[mini+1:]...)
}

// Process adds a pattern to the table and updates its label based on it's frequency.
// This implements the Herustic interface - so we should stop processing if we detect a JSON message by returning false.
func (p *PatternTable) Process(context *messageContext) bool {

	if context.tokens == nil {
		log.Error("Tokens are required to process user samples")
		return true
	}

	idx := p.insert(context.tokens)

	// If the log has an aggregate (default) label, but is the most popular,
	// we shouldn't aggreaget it.
	if idx == 0 && context.label == aggregate {
		context.label = noAggregate
		return true
	}

	return false
}
