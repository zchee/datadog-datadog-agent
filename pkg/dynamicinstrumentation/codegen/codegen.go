// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux_bpf

// Package codegen is used to generate bpf program source code based on probe definitions
package codegen

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"text/template"

	"github.com/DataDog/datadog-agent/pkg/dynamicinstrumentation/ditypes"
	"github.com/DataDog/datadog-agent/pkg/util/log"
)

// GenerateBPFParamsCode generates the source code associated with the probe and data
// in it's associated process info.
func GenerateBPFParamsCode(procInfo *ditypes.ProcessInfo, probe *ditypes.Probe) error {
	parameterBytes := []byte{}
	out := bytes.NewBuffer(parameterBytes)

	if probe.InstrumentationInfo.InstrumentationOptions.CaptureParameters {
		params := applyCaptureDepth(procInfo.TypeMap.Functions[probe.FuncName], probe.InstrumentationInfo.InstrumentationOptions.MaxReferenceDepth)
		applyFieldCountLimit(params)
		for i := range params {
			flattenedParams := flattenParameters([]ditypes.Parameter{params[i]})
			err := generateHeadersText(flattenedParams, out)
			if err != nil {
				return err
			}
			err = generateParametersTextViaLocationExpressions(flattenedParams, out)
			if err != nil {
				return err
			}
		}
	} else {
		log.Info("Not capturing parameters")
	}

	fmt.Println(">", out.String())
	probe.InstrumentationInfo.BPFParametersSourceCode = out.String()
	return nil
}

func resolveHeaderTemplate(param *ditypes.Parameter) (*template.Template, error) {
	switch param.Kind {
	case uint(reflect.String):
		if param.Location.InReg {
			return template.New("string_reg_header_template").Parse(stringRegisterHeaderTemplateText)
		}
		return template.New("string_stack_header_template").Parse(stringStackHeaderTemplateText)
	case uint(reflect.Slice):
		if param.Location.InReg {
			return template.New("slice_reg_header_template").Parse(sliceRegisterHeaderTemplateText)
		}
		return template.New("slice_stack_header_template").Parse(sliceStackHeaderTemplateText)
	default:
		return template.New("header_template").Parse(headerTemplateText)
	}
}

func generateHeadersText(params []ditypes.Parameter, out io.Writer) error {
	for i := range params {
		err := generateHeaderText(params[i], out)
		if err != nil {
			return err
		}
	}
	return nil
}

func generateHeaderText(param ditypes.Parameter, out io.Writer) error {
	if reflect.Kind(param.Kind) == reflect.Slice {
		return generateSliceHeader(&param, out)
	} else if reflect.Kind(param.Kind) == reflect.String {
		return generateStringHeader(&param, out)
	} else {
		tmplt, err := resolveHeaderTemplate(&param)
		if err != nil {
			return err
		}
		err = tmplt.Execute(out, param)
		if err != nil {
			return err
		}
		if len(param.ParameterPieces) != 0 {
			return generateHeadersText(param.ParameterPieces, out)
		}
	}
	return nil
}

func generateParametersTextViaLocationExpressions(params []ditypes.Parameter, out io.Writer) error {
	for i := range params {
		for _, locationExpression := range params[i].LocationExpressions {
			template, err := resolveLocationExpressionTemplate(locationExpression)
			if err != nil {
				return err
			}
			err = template.Execute(out, locationExpression)
			if err != nil {
				return fmt.Errorf("could not execute template for generating location expression: %w", err)
			}
		}
	}
	return nil
}

func resolveLocationExpressionTemplate(locationExpression ditypes.LocationExpression) (*template.Template, error) {
	if locationExpression.Opcode == ditypes.OpReadUserRegister {
		return template.New("read_location_expression").Parse(readRegisterTemplateText)
	}
	if locationExpression.Opcode == ditypes.OpPop {
		return template.New("pop_location_expression").Parse(popTemplateText)
	}
	if locationExpression.Opcode == ditypes.OpPopVariableLength {
		return template.New("pop_variable_length_location_expression").Parse(variablePopTemplateText)
	}
	if locationExpression.Opcode == ditypes.OpDereference {
		return template.New("dereference_location_expression").Parse(dereferenceTemplateText)
	}
	if locationExpression.Opcode == ditypes.OpDereferenceVariableLength {
		return template.New("dereference_variable_length_location_expression").Parse(variableDereferenceTemplateText)
	}
	if locationExpression.Opcode == ditypes.OpApplyOffset {
		return template.New("apply_offset_location_expression").Parse(applyOffsetTemplateText)
	}

	return nil, errors.New("invalid location expression opcode")
}

func cleanupTypeName(s string) string {
	return strings.TrimPrefix(s, "*")
}

func generateSliceHeader(slice *ditypes.Parameter, out io.Writer) error {
	if slice == nil {
		return errors.New("nil slice parameter when generating header code")
	}
	if len(slice.ParameterPieces) != 2 {
		return errors.New("invalid slice parameter when generating header code")
	}

	typeHeaderBytes := []byte{}
	typeHeaderBuf := bytes.NewBuffer(typeHeaderBytes)
	err := generateHeaderText(slice.ParameterPieces[0], typeHeaderBuf)
	if err != nil {
		return err
	}

	lengthHeaderBytes := []byte{}
	lengthHeaderBuf := bytes.NewBuffer(lengthHeaderBytes)
	err = generateSliceLengthHeader(slice.ParameterPieces[1], lengthHeaderBuf)
	if err != nil {
		return err
	}

	w := sliceHeaderWrapper{
		Parameter:           slice,
		SliceTypeHeaderText: typeHeaderBuf.String(),
		SliceLengthText:     lengthHeaderBuf.String(),
	}

	sliceTemplate, err := resolveHeaderTemplate(slice)
	if err != nil {
		return err
	}

	err = sliceTemplate.Execute(out, w)
	if err != nil {
		return fmt.Errorf("could not execute template for generating slice header: %w", err)
	}

	return nil
}

func generateStringHeader(stringParam *ditypes.Parameter, out io.Writer) error {
	if stringParam == nil {
		return errors.New("nil string parameter when generating header code")
	}
	if len(stringParam.ParameterPieces) != 2 {
		return fmt.Errorf("invalid string parameter when generating header code (pieces len %d)", len(stringParam.ParameterPieces))
	}

	x := []byte{}
	buf := bytes.NewBuffer(x)
	err := generateStringLengthHeader(stringParam.ParameterPieces[1], buf)
	if err != nil {
		return err
	}

	stringHeaderWrapper := stringHeaderWrapper{
		Parameter:        stringParam,
		StringLengthText: buf.String(),
	}

	stringTemplate, err := resolveHeaderTemplate(stringParam)
	if err != nil {
		return err
	}

	err = stringTemplate.Execute(out, stringHeaderWrapper)
	if err != nil {
		return fmt.Errorf("could not execute template for generating string header: %w", err)
	}
	return nil
}

func generateStringLengthHeader(stringLengthParamPiece ditypes.Parameter, buf *bytes.Buffer) error {
	var (
		tmplte *template.Template
		err    error
	)
	if stringLengthParamPiece.Location.InReg {
		tmplte, err = template.New("string_register_length_header").Parse(stringLengthRegisterTemplateText)
	} else {
		tmplte, err = template.New("string_stack_length_header").Parse(stringLengthStackTemplateText)
	}
	if err != nil {
		return err
	}
	return tmplte.Execute(buf, stringLengthParamPiece)
}

func generateSliceLengthHeader(sliceLengthParamPiece ditypes.Parameter, buf *bytes.Buffer) error {
	var (
		tmplte *template.Template
		err    error
	)
	if sliceLengthParamPiece.Location.InReg {
		tmplte, err = template.New("slice_register_length_header").Parse(sliceLengthRegisterTemplateText)
	} else {
		tmplte, err = template.New("slice_stack_length_header").Parse(sliceLengthStackTemplateText)
	}
	if err != nil {
		return err
	}
	return tmplte.Execute(buf, sliceLengthParamPiece)
}

type sliceHeaderWrapper struct {
	Parameter           *ditypes.Parameter
	SliceLengthText     string
	SliceTypeHeaderText string
}

type stringHeaderWrapper struct {
	Parameter        *ditypes.Parameter
	StringLengthText string
}
