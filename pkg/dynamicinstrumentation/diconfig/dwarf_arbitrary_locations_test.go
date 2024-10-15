package diconfig

import (
	"testing"

	"github.com/DataDog/datadog-agent/pkg/dynamicinstrumentation/ditypes"
	"github.com/DataDog/datadog-agent/pkg/dynamicinstrumentation/testutil"
	"github.com/stretchr/testify/assert"
)

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

	expectedB := &ditypes.Parameter{
		Name:            "b",
		ID:              "",
		Type:            "struct []uint8",
		TotalSize:       24,
		Kind:            0x17,
		Location:        ditypes.Location{InReg: false, StackOffset: -8},
		ParameterPieces: []ditypes.Parameter{},
	}

	expectedN := &ditypes.Parameter{
		Name:            "n",
		ID:              "",
		Type:            "uint64",
		TotalSize:       8,
		Kind:            0xb,
		Location:        ditypes.Location{InReg: true},
		ParameterPieces: []ditypes.Parameter{},
	}

	tcs := []struct {
		funcName string
		varName  string
		pc       uint64

		expected *ditypes.Parameter
	}{
		// b between 0x51858c and 0x518690 with several moves
		{"sample.Return_goroutine_id", "b", 0x518600, expectedB},
		// n between 0x518650 and 0x51865c
		{"sample.Return_goroutine_id", "n", 0x518658, expectedN},
	}
	for _, tc := range tcs {
		param, err := GetParameterAtPC(inspector, prefix+tc.funcName, tc.varName, tc.pc)
		assert.NoError(t, err)

		assert.Equal(t, tc.expected, param)
	}
}

func TestGetPCAtLine(t *testing.T) {
	curDir, err := pwd()
	if err != nil {
		t.Error(err)
	}

	binaryPath, err := testutil.BuildGoBinaryWrapper(curDir, "../testutil/sample/sample_service")
	if err != nil {
		t.Error(err)
	}

	inspector, err := loadDWARF(binaryPath)
	pc, err := GetPCAtLine(inspector, "/git/datadog-agent/pkg/dynamicinstrumentation/testutil/sample/other.go", 42)
	assert.NoError(t, err)
	assert.Equal(t, uint64(0x519eec), pc)
}
