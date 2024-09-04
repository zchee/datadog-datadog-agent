// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux

// Package kfilters holds kfilters related files
package kfilters

import (
	"fmt"

	"github.com/DataDog/datadog-agent/pkg/security/secl/compiler/eval"
	"github.com/DataDog/datadog-agent/pkg/security/secl/model"
	"github.com/DataDog/datadog-agent/pkg/security/secl/rules"
)

var mmapCapabilities = rules.FieldCapabilities{
	{
		Field:       "mmap.file.path",
		TypeBitmask: eval.ScalarValueType | eval.PatternValueType,
		ValidateFnc: validateBasenameFilter,
	},
	{
		Field:       "mmap.file.name",
		TypeBitmask: eval.ScalarValueType,
	},
	{
		Field:       "mmap.protection",
		TypeBitmask: eval.ScalarValueType | eval.BitmaskValueType,
	},
	{
		Field:       "mmap.flags",
		TypeBitmask: eval.ScalarValueType | eval.BitmaskValueType,
	},
}

func mmapKFilters(approvers rules.Approvers) (ActiveKFilters, error) {
	mmapKFilters, err := getBasenameKFilters(model.MMapEventType, "file", approvers)
	if err != nil {
		return nil, err
	}

	for field, values := range approvers {
		switch field {
		case "mmap.file.name", "mmap.file.path": // already handled by getBasenameKFilters
		case "mmap.flags":
			kfilter, err := getFlagsKFilters("mmap_flags_approvers", intValues[int32](values)...)
			if err != nil {
				return nil, err
			}
			mmapKFilters = append(mmapKFilters, kfilter)
		case "mmap.protection":
			kfilter, err := getFlagsKFilters("mmap_protection_approvers", intValues[int32](values)...)
			if err != nil {
				return nil, err
			}
			mmapKFilters = append(mmapKFilters, kfilter)
		default:
			return nil, fmt.Errorf("unknown field '%s'", field)
		}
	}
	return newActiveKFilters(mmapKFilters...), nil
}
