// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//revive:disable
package multilineexperiment

import (
	"unicode"
)

type Token uint

const (
	Space Token = iota

	// Special Characters
	Colon        // :
	Dash         // -
	FSlash       // /
	BSlash       // \
	Period       // .
	Comma        // ,
	SingleQuote  // '
	DoubleQuote  // "
	Star         // *
	Plus         // + - 10
	ParenOpen    // (
	ParenClose   // )
	BraceOpen    // {
	BraceClose   // }
	BracketOpen  // [
	BracketClose // ]

	// Special tokens
	Month
	Day

	// Digit runs
	D1 // 19
	D2
	D3
	D4
	D5
	D6
	D7
	D8
	D9
	D10

	// Char runs
	C1 // 29
	C2
	C3
	C4
	C5
	C6
	C7
	C8
	C9
	C10

	END
)

func getToken(char byte) Token {
	if unicode.IsDigit(rune(char)) {
		return D1
	} else if unicode.IsSpace(rune(char)) {
		return Space
	}

	switch char {
	case ':':
		return Colon
	case '-':
		return Dash
	case '/':
		return FSlash
	case '\\':
		return BSlash
	case '.':
		return Period
	case ',':
		return Comma
	case '\'':
		return SingleQuote
	case '"':
		return DoubleQuote
	case '*':
		return Star
	case '+':
		return Plus
	case '(':
		return ParenOpen
	case ')':
		return ParenClose
	case '{':
		return BraceOpen
	case '}':
		return BraceClose
	case '[':
		return BracketOpen
	case ']':
		return BracketClose
	}

	return C1
}

func tokenize(input []byte, len int) []Token {
	tokens := make([]Token, 0, len)

	run := 0
	lastToken := getToken(input[0])

	insertToken := func() {
		if lastToken == C1 || lastToken == D1 {
			if run > 9 {
				run = 9
			}
			if lastToken == C1 || lastToken == D1 {
				tokens = append(tokens, lastToken+Token(run))
			}
		} else {
			tokens = append(tokens, lastToken)
		}
		run = 0
	}

	for _, char := range input[1:] {
		currentToken := getToken(char)
		if currentToken != lastToken {
			insertToken()
		} else {
			run += 1
		}

		lastToken = currentToken
	}

	insertToken()

	return tokens
}

func isMatch(setA []Token, setB []Token, thresh float64) bool {
	count := len(setA)
	if len(setB) < count {
		count = len(setB)
	}

	match := 0
	for i := 0; i < count; i++ {
		if setA[i] == setB[i] {
			match++
		}
	}

	return float64(match)/float64(count) >= thresh
}

// func tokensToString(tokens []Token) string {

// }
