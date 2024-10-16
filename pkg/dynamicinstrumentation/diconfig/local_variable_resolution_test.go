package diconfig

import (
	"testing"

	"github.com/DataDog/datadog-agent/pkg/dynamicinstrumentation/ditypes"
	"github.com/DataDog/datadog-agent/pkg/dynamicinstrumentation/testutil"
	"github.com/stretchr/testify/assert"
)

func TestGetPCAtLine(t *testing.T) {
	// log.SetupLogger(seelog.Default, "debug")
	curDir, err := pwd()
	if err != nil {
		t.Error(err)
	}

	binaryPath, err := testutil.BuildGoBinaryWrapper(curDir, "../testutil/sample/sample_service")
	if err != nil {
		t.Error(err)
	}

	inspector, err := loadDWARF(binaryPath)
	pc, err := GetPCAtLine(inspector, "datadog-agent/pkg/dynamicinstrumentation/testutil/sample/other.go", 42)
	assert.NoError(t, err)
	assert.Equal(t, uint64(0x519eec), pc)
}

func TestGetParameterAtPC(t *testing.T) {
	// log.SetupLogger(seelog.Default, "debug")

	curDir, err := pwd()
	if err != nil {
		t.Error(err)
	}

	binaryPath, err := testutil.BuildGoBinaryWrapper(curDir, "../testutil/sample/sample_service")
	if err != nil {
		t.Error(err)
	}

	inspector, err := loadDWARF(binaryPath)
	assert.NoError(t, err)

	prefix := "github.com/DataDog/datadog-agent/pkg/dynamicinstrumentation/testutil/"

	// sample.Return_goroutine_id is other.go and returns at line 31
	// TODO: resolve files by suffix match instead of full path
	pc, err := GetPCAtLine(inspector, "datadog-agent/pkg/dynamicinstrumentation/testutil/sample/other.go", 32)
	assert.NoError(t, err)

	tcs := []struct {
		funcName string
		varName  string
		pc       uint64

		expected *ditypes.Parameter
	}{
		{"sample.Return_goroutine_id", "b", pc, &ditypes.Parameter{
			Name:            "b",
			ID:              "",
			Type:            "struct []uint8",
			TotalSize:       24,
			Kind:            0x17,
			Location:        ditypes.Location{InReg: false, StackOffset: -16},
			ParameterPieces: []ditypes.Parameter{},
		}},
		{"sample.Return_goroutine_id", "n", pc, &ditypes.Parameter{
			Name:            "n",
			ID:              "",
			Type:            "uint64",
			TotalSize:       8,
			Kind:            0xb,
			Location:        ditypes.Location{InReg: true},
			ParameterPieces: []ditypes.Parameter{},
		}},
	}
	for _, tc := range tcs {
		param, err := GetParameterAtPC(inspector, prefix+tc.funcName, tc.varName, tc.pc)
		assert.NoError(t, err)

		assert.Equal(t, tc.expected, param)
	}
}

func TestGetVariablesAtPC(t *testing.T) {
	// log.SetupLogger(seelog.Default, "info")

	curDir, err := pwd()
	if err != nil {
		t.Error(err)
	}

	binaryPath, err := testutil.BuildGoBinaryWrapper(curDir, "../testutil/sample/sample_service")
	if err != nil {
		t.Error(err)
	}

	inspector, err := loadDWARF(binaryPath)

	// same line used as in TestGetPCAtLine, last line in test_variable_capture
	pc, err := GetPCAtLine(inspector, "datadog-agent/pkg/dynamicinstrumentation/testutil/sample/other.go", 42)
	assert.NoError(t, err)
	assert.Equal(t, uint64(0x519eec), pc)

	vars, err := GetVariablesAtPC(inspector, pc)
	assert.NoError(t, err)

	assert.NoError(t, err)
	expected := []*ditypes.Parameter{{
		Name:            "localVariable",
		Type:            "int",
		TotalSize:       8,
		Kind:            0x2,
		Location:        ditypes.Location{InReg: false, StackOffset: -32},
		ParameterPieces: []ditypes.Parameter{},
	}}
	assert.Equal(t, expected, vars)
}
