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
				ditypes.LocationExpression{
					Opcode:        ditypes.OpReadUserRegister,
					Arg1:          uint(parameterMetadata.Pieces[0].Register),
					Arg2:          8,
					InstructionID: randomID(),
				},
				ditypes.LocationExpression{
					Opcode:        ditypes.OpPop,
					Arg1:          8,
					InstructionID: randomID(),
				},
			)
		}
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
