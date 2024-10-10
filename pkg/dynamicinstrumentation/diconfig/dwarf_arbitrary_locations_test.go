package diconfig

import (
	"debug/elf"
	"testing"

	"github.com/DataDog/datadog-agent/pkg/dynamicinstrumentation/ditypes"
	"github.com/DataDog/datadog-agent/pkg/dynamicinstrumentation/testutil"
	"github.com/stretchr/testify/assert"
)

func TestGetParameterAtPC(t *testing.T) {
	curDir, err := pwd()
	if err != nil {
		t.Error(err)
	}

	binaryPath, err := testutil.BuildGoBinaryWrapper(curDir, "../testutil/sample/sample_service")
	if err != nil {
		t.Error(err)
	}

	dwarfData, err := loadDWARF(binaryPath)
	assert.NoError(t, err)

	elfFile, err := elf.Open(binaryPath)
	assert.NoError(t, err)

	d := &dwarfInspector{
		elf: elfMetadata{
			file: elfFile,
			arch: GoArchARM64,
		},
		dwarfData: dwarfData,
	}

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
		param, err := GetParameterAtPC(d, prefix+tc.funcName, tc.varName, tc.pc)
		assert.NoError(t, err)

		assert.Equal(t, tc.expected, param)
	}

	// t.Fatalf("Show me the output")
}
