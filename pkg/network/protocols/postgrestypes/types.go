// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

//go:build ignore

package postgrestypes

/*
#include "../../ebpf/c/protocols/postgres/types.h"
#include "../../ebpf/c/protocols/classification/defs.h"
*/
import "C"

// This const is being used in system_probe as default buffer size for telemetry.
// It is being used in a different package to avoid cyclic dependencies.

const (
	BufferSize = C.POSTGRES_BUFFER_SIZE
)
