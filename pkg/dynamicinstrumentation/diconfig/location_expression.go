// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux_bpf

package diconfig

import (
	"math/rand"
	"reflect"

	"github.com/DataDog/datadog-agent/pkg/dynamicinstrumentation/ditypes"

	"github.com/DataDog/datadog-agent/pkg/network/go/bininspect"
)

func GenerateLocationExpression(parameterMetadata bininspect.ParameterMetadata) []ditypes.LocationExpression {

	expressions := []ditypes.LocationExpression{}

	if parameterMetadata.Kind == reflect.Uint {
		if parameterMetadata.Pieces[0].InReg {
			expressions = append(expressions,
				ditypes.ReadRegisterLocationExpression(uint(parameterMetadata.Pieces[0].Register), 8),
				ditypes.PopLocationExpression(8),
			)
		}
	} else if parameterMetadata.Kind == reflect.Pointer {
		if parameterMetadata.Pieces[0].InReg {
			expressions = append(expressions,
				ditypes.ReadRegisterLocationExpression(uint(parameterMetadata.Pieces[0].Register), 8),
				ditypes.ApplyOffsetLocationExpression(0),
				ditypes.DereferenceLocationExpression(8),
				ditypes.PopLocationExpression(8),

				ditypes.ReadRegisterLocationExpression(uint(parameterMetadata.Pieces[0].Register), 8),
				ditypes.ApplyOffsetLocationExpression(8),
				ditypes.DereferenceLocationExpression(1),
				ditypes.PopLocationExpression(1),

				ditypes.ReadRegisterLocationExpression(uint(parameterMetadata.Pieces[0].Register), 8),
				ditypes.PopLocationExpression(8),
			)
		}
	} else if parameterMetadata.Kind == reflect.Struct {
		expressions = append(expressions,
			ditypes.ReadRegisterLocationExpression(uint(parameterMetadata.Pieces[0].Register), 8),
			ditypes.PopLocationExpression(8),
			ditypes.ReadRegisterLocationExpression(uint(parameterMetadata.Pieces[1].Register), 8),
		)
	} else if parameterMetadata.Kind == reflect.String {
		expressions = append(expressions,
			ditypes.ReadRegisterLocationExpression(0, 8),
			ditypes.ReadRegisterLocationExpression(1, 8),
			ditypes.DereferenceDynamicLocationExpression(20, 1),
			ditypes.PopDynamicLocationExpression(20),
		)
	} else if parameterMetadata.Kind == reflect.Slice {
		expressions = append(expressions,
			ditypes.ReadRegisterLocationExpression(0, 8),
			ditypes.ReadRegisterLocationExpression(1, 8),
			ditypes.DereferenceDynamicLocationExpression(3, 8),
			ditypes.PopDynamicLocationExpression(24),
		)
	}
	return expressions
}

func randomID() string {
	length := 6
	randomString := make([]byte, length)
	for i := 0; i < length; i++ {
		randomString[i] = byte(65 + rand.Intn(25))
	}
	return string(randomString)
}
