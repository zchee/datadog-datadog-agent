// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

// Package automultilinedetection contains auto multiline detection and aggregation logic.
package automultilinedetection

import (
	"bytes"
	"unicode"
)

// The tokenizer is used to convert a log message (string of bytes) into a list of tokens that
// represents the underlying structure of the log. The string of tokens is a compact slice of bytes
// that can be used to compare log messages for similarity.

// Token is the type that represents a single token.
type Token byte

// maxRun is the maximum run of a char or digit before it is capped.
// Note: This must not exceed D10 or C10 below.
const maxRun = 10

//revive:disable
const (
	Space Token = iota

	// Special Characters
	Colon        // :
	Semicolon    // ;
	Dash         // -
	Underscore   // _
	FSlash       // /
	BSlash       // \
	Period       // .
	Comma        // ,
	SingleQuote  // '
	DoubleQuote  // "
	Backtick     // `
	Tilda        // ~
	Star         // *
	Plus         // +
	Equal        // =
	ParenOpen    // (
	ParenClose   // )
	BraceOpen    // {
	BraceClose   // }
	BracketOpen  // [
	BracketClose // ]
	Ampersand    // &
	Exclamation  // !
	At           // @
	Pound        // #
	Dollar       // $
	Percent      // %
	UpArrow      // ^

	// Digit runs
	D1
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
	C1
	C2
	C3
	C4
	C5
	C6
	C7
	C8
	C9
	C10

	// Special tokens
	Month
	Day
	APM // AM or PM
	Zone
	T
	Z

	END // Not used as a token. Used to mark the end of the token list
)

//revive:enable

// getToken returns a single token from a single byte.
func getToken(char byte) Token {
	if unicode.IsDigit(rune(char)) {
		return D1
	} else if unicode.IsSpace(rune(char)) {
		return Space
	}

	switch char {
	case ':':
		return Colon
	case ';':
		return Semicolon
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
	case '`':
		return Backtick
	case '~':
		return Tilda
	case '*':
		return Star
	case '+':
		return Plus
	case '=':
		return Equal
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
	case '&':
		return Ampersand
	case '!':
		return Exclamation
	case '@':
		return At
	case '#':
		return Pound
	case '$':
		return Dollar
	case '%':
		return Percent
	case '^':
		return UpArrow
	}

	return C1
}

func getSpecialShortToken(char byte) Token {
	switch char {
	case 'T':
		return T
	case 'Z':
		return Z
	}
	return END
}

func getSpecialLongToken(input string) Token {
	switch input {
	case "JAN", "FEB", "MAR", "APR", "MAY", "JUN", "JUL",
		"AUG", "SEP", "OCT", "NOV", "DEC":
		return Month
	case "MON", "TUE", "WED", "THU", "FRI", "SAT", "SUN":
		return Day
	case "AM", "PM":
		return APM
	case "UTC", "GMT", "EST", "EDT", "CST", "CDT",
		"MST", "MDT", "PST", "PDT", "JST", "KST",
		"IST", "MSK", "CEST", "CET", "BST", "NZST",
		"NZDT", "ACST", "ACDT", "AEST", "AEDT",
		"AWST", "AWDT", "AKST", "AKDT", "HST",
		"HDT", "CHST", "CHDT", "NST", "NDT":
		return Zone
	}

	return END
}

// tokenize converts a byte slice to a list of tokens.
func tokenize(input []byte) []Token {
	// len(tokens) will always be <= len(input)
	tokens := make([]Token, 0, len(input))

	run := 0
	lastToken := getToken(input[0])
	strBuf := bytes.NewBuffer([]byte{byte(unicode.ToUpper(rune(input[0])))})

	insertToken := func() {
		defer func() {
			run = 0
			strBuf.Reset()
		}()
		// If the buffer is not empty, check if it is a special token
		if strBuf.Len() == 1 {
			if specialToken := getSpecialShortToken(strBuf.Bytes()[0]); specialToken != END {
				tokens = append(tokens, specialToken)
				return
			}
		} else if strBuf.Len() > 1 {
			if specialToken := getSpecialLongToken(strBuf.String()); specialToken != END {
				tokens = append(tokens, specialToken)
				return
			}
		}

		// Check for char or digit runs
		if lastToken == C1 || lastToken == D1 {
			// Limit max run size
			if run >= maxRun {
				run = maxRun - 1
			}
			tokens = append(tokens, lastToken+Token(run))
		} else {
			tokens = append(tokens, lastToken)
		}
	}

	for _, char := range input[1:] {
		currentToken := getToken(char)
		if currentToken != lastToken {
			insertToken()
		} else {
			run++
		}
		if currentToken == C1 {
			strBuf.WriteByte(byte(unicode.ToUpper(rune(char))))
		} else {
			strBuf.WriteByte(char)
		}
		lastToken = currentToken
	}

	insertToken()

	return tokens
}

// tokenToString converts a single token to a debug string.
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
	case Semicolon:
		return ";"
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
	case Backtick:
		return "`"
	case Tilda:
		return "~"
	case Star:
		return "*"
	case Plus:
		return "+"
	case Equal:
		return "="
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
	case Ampersand:
		return "&"
	case Exclamation:
		return "!"
	case At:
		return "@"
	case Pound:
		return "#"
	case Dollar:
		return "$"
	case Percent:
		return "%"
	case UpArrow:
		return "^"
	case Month:
		return "MTH"
	case Day:
		return "DAY"
	case APM:
		return "PM"
	case T:
		return "T"
	case Z:
		return "Z"
	case Zone:
		return "ZONE"
	}

	return ""
}

// tokensToString converts a list of tokens to a debug string.
func tokensToString(tokens []Token) string {
	str := ""
	for _, t := range tokens {
		str += tokenToString(t)
	}
	return str
}

// Tokenizer is a heuristic to compute tokens from a log message.
type Tokenizer struct {
	maxEvalBytes int
}

// NewTokenizer returns a new Tokenizer detection heuristic.
func NewTokenizer(maxEvalBytes int) *Tokenizer {
	return &Tokenizer{
		maxEvalBytes: maxEvalBytes,
	}
}

// Process enriches the message context with tokens.
// This implements the Herustic interface - this heuristic does not stop processing.
func (t *Tokenizer) Process(context *messageContext) bool {
	maxBytes := len(context.rawMessage)
	if maxBytes > t.maxEvalBytes {
		maxBytes = t.maxEvalBytes
	}
	context.tokens = tokenize(context.rawMessage[:maxBytes])
	return true
}
