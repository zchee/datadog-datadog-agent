package multilineexperiment

import (
	"testing"
)

const tokenLength = 40

var samples = []string{
	"12-12-12T12:12:21Z12:12",
	"ab ab 1 1:1:1 1",
	"ab ab 1 1:1:1 abc 12",
	"ab ab 1 1:1:1 +2 1",
	"12 av 12 12:12 ab",
	"12 ab 12 12:12 -12",
	"ab, 12-ab-12 12:12:12 ab",
	"ab, 12 ab 12 12:12:12 ab",
	"ab, 12 ab 12 12:12:12 -1",
	"12-12-12T12:12:12.12T12:12",
	"12-12-12 12:12:12,1",
	"ab 12, 12 12:12:12 AM",
	"1234-12-21",
}

func BenchmarkTestModel(b *testing.B) {
	m := compileModel(tokenLength)

	b.ResetTimer()

	for n := 0; n < b.N; n++ {
		for _, s := range samples {
			m.MatchProbability(tokenize([]byte(s), len(s)))
		}
	}
}
