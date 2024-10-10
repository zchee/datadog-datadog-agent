package diconfig

import (
	"debug/elf"
	"testing"

	"github.com/DataDog/datadog-agent/pkg/dynamicinstrumentation/testutil"
	"github.com/stretchr/testify/assert"
)

func TestGetLocation(t *testing.T) {
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

	tcs := []struct {
		funcName string
		varName  string
		pc       uint64
	}{
		// b between 0x51858c and 0x518690 with several moves
		{"sample.Return_goroutine_id", "b", 0x51858c},
		// n between 0x518650 and 0x51865c
		{"sample.Return_goroutine_id", "n", 0x518650},
		{"sample.Return_goroutine_id", "n", 0x518658},
		{"sample.Return_goroutine_id", "n", 0x51865b},
	}
	for _, tc := range tcs {
		loc, err := GetLocation(d, prefix+tc.funcName, tc.varName, tc.pc)
		assert.NoError(t, err)
		assert.NotNil(t, loc)
	}

	t.Fatalf("Show me the output")
}
