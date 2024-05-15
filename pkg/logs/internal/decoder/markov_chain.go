// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//revive:disable
package decoder

import (
	"math"
)

type MarkovChain struct {
	countTable [][]uint
}

func NewMarkovChain() *MarkovChain {
	return &MarkovChain{
		countTable: make([][]uint, END),
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

func (m *MarkovChain) MatchProbability(tokens []Token) float64 {
	out := make([]uint, len(tokens)-1)

	lastToken := tokens[0]
	for i, token := range tokens[1:] {
		if m.countTable[lastToken] != nil && m.countTable[lastToken][token] > 0 {
			out[i] = 1
		}
		lastToken = token
	}
	trimmed := trimStateSet(out)
	// fmt.Println(trimmed)
	if len(trimmed) < 5 {
		return 0
	}
	return geoMean(trimmed)
}

// Removes leading and trailing zeros
func trimStateSet(states []uint) []uint {
	start := 0
	for i, n := range states {
		if n != 0 {
			start = i
			break
		}
	}

	end := len(states)
	for i := len(states) - 1; i >= 0; i-- {
		if states[i] != 0 {
			end = i + 1
			break
		}
	}

	return states[start:end]
}

// func avg(states []uint) float64 {
// 	sum := float64(0)
// 	for _, n := range states {
// 		sum += float64(n)
// 	}

// 	return sum / float64(len(states))
// }

func geoMean(states []uint) float64 {
	prod := float64(1)
	for _, n := range states {
		if n == 0 {
			prod *= 0.01
		} else {
			prod = prod * float64(n)
		}
	}

	return math.Pow(prod, 1/float64(len(states)))
}
