// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

// Package automultilinedetection contains auto multiline detection and aggregation logic.
package automultilinedetection

import (
	"testing"
)

func BenchmarkTokenizer(b *testing.B) {
	for n := 0; n < b.N; n++ {
		tokenize([]byte("Sun Mar 2PM EST JAN FEB MAR !@#$%^&*()_+[]:-/\\.,\\'{}\"`~ NZST ACDT CHST T!Z(T)Z#AM 123-abc-[foo] (bar) 12-12-12T12:12:12.12T12:12Z123"))
	}
}
