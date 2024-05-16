// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

// Package decoder contains the multi-line experiment code.
package decoder

import (
	"strings"
	"unicode"
)

//revive:disable
type Token uint

const (
	Space Token = iota

	// Special Characters
	Colon        // :
	Dash         // -
	Underscore   // _
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

	// Special
	MTH
	AM
	PM
	DAY
	ZONE
	T
	Z

	END
)

var specialMap = map[string]Token{
	"JAN":  Month,
	"FEB":  Month,
	"MAR":  Month,
	"APR":  Month,
	"MAY":  Month,
	"JUN":  Month,
	"JUL":  Month,
	"AUG":  Month,
	"SEP":  Month,
	"OCT":  Month,
	"NOV":  Month,
	"DEC":  Month,
	"MON":  Day,
	"TUE":  Day,
	"WED":  Day,
	"THU":  Day,
	"FRI":  Day,
	"SAT":  Day,
	"SUN":  Day,
	"AM":   AM,
	"PM":   PM,
	"UTC":  ZONE,
	"GMT":  ZONE,
	"EST":  ZONE,
	"EDT":  ZONE,
	"CST":  ZONE,
	"CDT":  ZONE,
	"MST":  ZONE,
	"MDT":  ZONE,
	"PST":  ZONE,
	"PDT":  ZONE,
	"JST":  ZONE,
	"KST":  ZONE,
	"IST":  ZONE,
	"MSK":  ZONE,
	"CEST": ZONE,
	"CET":  ZONE,
	"BST":  ZONE,
	"NZST": ZONE,
	"NZDT": ZONE,
	"ACST": ZONE,
	"ACDT": ZONE,
	"AEST": ZONE,
	"AEDT": ZONE,
	"AWST": ZONE,
	"AWDT": ZONE,
	"AKST": ZONE,
	"AKDT": ZONE,
	"HST":  ZONE,
	"HDT":  ZONE,
	"CHST": ZONE,
	"CHDT": ZONE,
	"NST":  ZONE,
	"NDT":  ZONE,
	"T":    T,
	"Z":    Z,
}

//revive:enable

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
	case '_':
		return Underscore
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

func tokenize(input []byte, leng int) []Token {
	tokens := make([]Token, 0, leng)

	run := 0
	lastToken := getToken(input[0])
	strBuf := []byte{input[0]}

	insertToken := func() {
		defer func() {
			run = 0
			strBuf = []byte{}
		}()
		if len(strBuf) > 0 {
			if specialToken, ok := specialMap[strings.ToUpper(string(strBuf))]; ok {
				tokens = append(tokens, specialToken)
				return
			}
		}
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
	}

	for _, char := range input[1:] {
		currentToken := getToken(char)
		if currentToken != lastToken {
			insertToken()
			strBuf = append(strBuf, char)
		} else {
			run++
			strBuf = append(strBuf, char)
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

func tokenToString(token Token) string {
	if token >= D1 && token <= D10 {
		t := ""
		for i := 0; i <= int(token-D1); i++ {
			t += "D"
		}
		return t
	} else if token >= C1 && token <= C10 {
		t := ""
		for i := 0; i <= int(token-C1); i++ {
			t += "C"
		}
		return t
	}

	switch token {
	case Space:
		return " "
	case Colon:
		return ":"
	case Dash:
		return "-"
	case Underscore:
		return "_"
	case FSlash:
		return "/"
	case BSlash:
		return "\\"
	case Period:
		return "."
	case Comma:
		return ","
	case SingleQuote:
		return "'"
	case DoubleQuote:
		return "\""
	case Star:
		return "*"
	case Plus:
		return "+"
	case ParenOpen:
		return "("
	case ParenClose:
		return ")"
	case BraceOpen:
		return "{"
	case BraceClose:
		return "}"
	case BracketOpen:
		return "["
	case BracketClose:
		return "]"
	case Month:
		return "MTH"
	case Day:
		return "DAY"
	case AM:
		return "AM"
	case PM:
		return "PM"
	case T:
		return "T"
	case Z:
		return "Z"
	case ZONE:
		return "ZONE"
	}

	return ""
}

func tokensToString(tokens []Token) string {

	str := ""
	for _, t := range tokens {
		str += tokenToString(t)
	}
	return str
}
