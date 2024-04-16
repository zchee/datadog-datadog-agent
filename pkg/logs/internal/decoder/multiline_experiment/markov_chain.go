// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//revive:disable
package multilineexperiment

import "math"

type MarkovChain struct {
	countTable      [][]uint
	transitionTable [][]float64
}

func NewMarkovChain() *MarkovChain {
	return &MarkovChain{
		countTable:      make([][]uint, END),
		transitionTable: make([][]float64, END),
	}
}

func (m *MarkovChain) Add(tokens []Token) {
	lastToken := tokens[0]
	for _, token := range tokens[1:] {
		if m.countTable[lastToken] == nil {
			m.countTable[lastToken] = make([]uint, END)
		}
		m.countTable[lastToken][token] += 1
		lastToken = token
	}
}

func (m *MarkovChain) Compile() {
	for i, neighbors := range m.countTable {
		m.transitionTable[i] = make([]float64, END)

		total := 0
		for _, count := range neighbors {
			if count > 0 {
				total += int(count)
			}
		}

		for k, count := range neighbors {
			m.transitionTable[i][k] = float64(count) / float64(total)
		}
	}
}

func (m *MarkovChain) TestFit(tokens []Token) float64 {
	out := make([]float64, len(tokens)-1)

	lastToken := tokens[0]
	for i, token := range tokens[1:] {
		out[i] = m.transitionTable[lastToken][token]
		lastToken = token
	}
	return geoMean(out)
}

func geoMean(states []float64) float64 {
	prod := float64(1)
	for _, n := range states {
		if n == 0 {
			prod *= 0.01
		} else {
			prod = prod * n
		}
	}

	return math.Pow(prod, 1/float64(len(states)))
}
