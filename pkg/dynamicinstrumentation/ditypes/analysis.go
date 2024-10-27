// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux_bpf

package ditypes

import (
	"debug/dwarf"
	"fmt"

	"golang.org/x/exp/rand"
)

// TypeMap contains all the information about functions and their parameters including
// functions that have been inlined in the binary
type TypeMap struct {
	// Functions maps fully-qualified function names to a slice of its parameters
	Functions map[string][]Parameter

	// InlinedFunctions maps program counters to a slice of dwarf entries used
	// when resolving stack traces that include inlined functions
	InlinedFunctions map[uint64][]*dwarf.Entry

	// FunctionsByPC places DWARF subprogram (function) entries in order by
	// its low program counter which is necessary for resolving stack traces
	FunctionsByPC []*LowPCEntry

	// DeclaredFiles places DWARF compile unit entries in order by its
	// low program counter which is necessary for resolving declared file
	// for the sake of stack traces
	DeclaredFiles []*LowPCEntry
}

// Parameter represents a function parameter as read from DWARF info
type Parameter struct {
	Name                string
	ID                  string
	Type                string
	TotalSize           int64
	Kind                uint
	Location            Location
	LocationExpressions []LocationExpression
	NotCaptureReason    NotCaptureReason
	ParameterPieces     []Parameter
}

func (p Parameter) String() string {
	return fmt.Sprintf("%s %s", p.Name, p.Type)
}

// NotCaptureReason is used to convey why a parameter was not captured
type NotCaptureReason uint8

const (
	Unsupported         NotCaptureReason = iota + 1 // Unsupported means the data type of the parameter is unsupported
	NoFieldLocation                                 // NoFieldLocation means the parameter wasn't captured because location information is missing from analysis
	FieldLimitReached                               // FieldLimitReached means the parameter wasn't captured because the data type has too many fields
	CaptureDepthReached                             // CaptureDepthReached means the parameter wasn't captures because the data type has too many levels
)

// SpecialKind is used for clarity in generated events that certain fields weren't read
type SpecialKind uint8

const (
	KindUnsupported         = 255 - iota // KindUnsupported is for unsupported types
	KindCutFieldLimit                    // KindCutFieldLimit is for fields that were cut because of field limit
	KindCaptureDepthReached              // KindCaptureDepthReached is for fields that were cut because of depth limit
)

func (s SpecialKind) String() string {
	switch s {
	case KindUnsupported:
		return "Unsupported"
	case KindCutFieldLimit:
		return "CutFieldLimit"
	default:
		return fmt.Sprintf("%d", s)
	}
}

type LocationExpressionOpcode uint

const (
	OpInvalid LocationExpressionOpcode = iota
	OpReadUserRegister
	OpReadUserStack
	OpReadUserRegisterToOutput
	OpReadUserStackToOutput
	OpDereference
	OpDereferenceToOutput
	OpDereferenceLarge
	OpDereferenceLargeToOutput
	OpApplyOffset
	OpPop
)

// Arg1 = register
// Arg2 = size of element
func ReadRegisterLocationExpression(register, size uint) LocationExpression {
	return LocationExpression{Opcode: OpReadUserRegister, Arg1: register, Arg2: size, InstructionID: randomID()}
}

// Arg1 = stack offset
// Arg2 = size of element
func ReadStackLocationExpression(offset, size uint) LocationExpression {
	return LocationExpression{Opcode: OpReadUserStack, Arg1: offset, Arg2: size, InstructionID: randomID()}
}

// Arg1 = register
// Arg2 = size of element
func ReadRegisterToOutputLocationExpression(register, size uint) LocationExpression {
	return LocationExpression{Opcode: OpReadUserRegisterToOutput, Arg1: register, Arg2: size, InstructionID: randomID()}
}

// Arg1 = stack offset
// Arg2 = size of element
func ReadStackToOutputLocationExpression(offset, size uint) LocationExpression {
	return LocationExpression{Opcode: OpReadUserStackToOutput, Arg1: offset, Arg2: size, InstructionID: randomID()}
}

// Arg1 = size of value we're reading from the 8 byte address at the top of the stack
func DereferenceLocationExpression(valueSize uint) LocationExpression {
	return LocationExpression{Opcode: OpDereference, Arg1: valueSize, InstructionID: randomID()}
}

// Arg1 = size of value we're reading from the 8 byte address at the top of the stack
func DereferenceToOutputLocationExpression(valueSize uint) LocationExpression {
	return LocationExpression{Opcode: OpDereferenceToOutput, Arg1: valueSize, InstructionID: randomID()}
}

// Arg1 = size in bytes of value we're reading from the 8 byte address at the top of the stack
// Arg2 = number of chunks (should be ({{.Arg1}} + 7) / 8)
func DereferenceLargeLocationExpression(typeSize uint) LocationExpression {
	return LocationExpression{Opcode: OpDereferenceLarge, Arg1: typeSize, Arg2: (typeSize + 7) / 8, InstructionID: randomID()}
}

// Arg1 = size in bytes of value we're reading from the 8 byte address at the top of the stack
// Arg2 = number of chunks (should be ({{.Arg1}} + 7) / 8)
func DereferenceLargeToOutputLocationExpression(typeSize uint) LocationExpression {
	return LocationExpression{Opcode: OpDereferenceLargeToOutput, Arg1: typeSize, Arg2: (typeSize + 7) / 8, InstructionID: randomID()}
}

// Arg1 = uint value (offset) we're adding to the 8-byte address on top of the stack
func ApplyOffsetLocationExpression(offset uint) LocationExpression {
	return LocationExpression{Opcode: OpApplyOffset, Arg1: offset, InstructionID: randomID()}
}

// Arg1 = number of elements to pop
// Arg2 = size of each element
func PopLocationExpression(numElements, elementSize uint) LocationExpression {
	return LocationExpression{Opcode: OpPop, Arg1: numElements, Arg2: elementSize, InstructionID: randomID()}
}

type LocationExpression struct {
	Opcode        LocationExpressionOpcode
	Arg1          uint
	Arg2          uint
	InstructionID string
}

// Location represents where a particular datatype is found on probe entry
type Location struct {
	InReg            bool
	StackOffset      int64
	Register         int
	NeedsDereference bool
	PointerOffset    uint64
}

func (l Location) String() string {
	return fmt.Sprintf("Location{InReg: %t, StackOffset: %d, Register: %d}", l.InReg, l.StackOffset, l.Register)
}

// LowPCEntry is a helper type used to sort DWARF entries by their low program counter
type LowPCEntry struct {
	LowPC uint64
	Entry *dwarf.Entry
}

// BPFProgram represents a bpf program that's created for a single probe
type BPFProgram struct {
	ProgramText string

	// Used for bpf code generation
	Probe *Probe
}

func randomID() string {
	length := 6
	randomString := make([]byte, length)
	for i := 0; i < length; i++ {
		randomString[i] = byte(65 + rand.Intn(25))
	}
	return string(randomString)
}
