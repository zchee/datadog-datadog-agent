// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

//go:build !linux_bpf

package modules

import "errors"

// GetBTFLoaderInfo is not supported on windows
func GetBTFLoaderInfo() (string, error) {
	return "", errors.New("GetBTFLoaderInfo not supported without linux_bpf")
}
