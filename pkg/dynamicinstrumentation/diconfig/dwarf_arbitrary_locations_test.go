package diconfig

import (
	"debug/elf"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetLocation(t *testing.T) {
	binaryPath := "testdata/sample"

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
	// locListData, err := godwarf.GetDebugSectionElf(elfFile, "loc")
	// if err != nil {
	// 	t.Fatalf("No .debug_loc section found: %v", err)
	// 	return
	// }

	_, err = GetLocation2(d, "main.return_goroutine_id", "b", 0x837fe8)
	assert.NoError(t, err)

	// assert.NotNil(t, varLocation)

	_, err = GetLocation2(d, "main.return_goroutine_id", "n", 0x83801c)

	_, err = GetLocation2(d, "main.return_goroutine_id", "n", 0x838020)

	_, err = GetLocation2(d, "main.return_goroutine_id", "n", 0x838028)
	assert.NoError(t, err)

	// assert.NotNil(t, varLocation)

	t.Fatalf("Show me the output")
}
