// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package sample

import (
	"bytes"
	"fmt"
	"math/rand"
	"runtime"
	"strconv"
)

type triggerVerifierErrorForTesting byte

//nolint:all
//go:noinline
func test_trigger_verifier_error(t triggerVerifierErrorForTesting) {}

// return_goroutine_id gets the goroutine ID and returns it
//
//nolint:all
//go:noinline
func Return_goroutine_id() uint64 {
	b := make([]byte, 64)
	b = b[:runtime.Stack(b, false)]
	b = bytes.TrimPrefix(b, []byte("goroutine "))
	b = b[:bytes.IndexByte(b, ' ')]
	n, _ := strconv.ParseUint(string(b), 10, 64)
	return n
}

//nolint:all
//go:noinline
func test_capture_variables() int {
	a := 123
	localVariable := rand.Intn(100)
	fmt.Println(localVariable)
	a = 42
	return a * localVariable
}

type Receiver struct {
	num int
}

//nolint:all
//go:noinline
func (r *Receiver) test_method_with_receiver() {
	fmt.Println(r.num)
}

var r = &Receiver{42}

//nolint:all
//go:noinline
func ExecuteOther() {
	test_trigger_verifier_error(1)
	test_capture_variables()
	r.test_method_with_receiver()
}
