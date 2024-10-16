package diconfig

import (
	"debug/dwarf"
	"fmt"

	"github.com/DataDog/datadog-agent/pkg/dynamicinstrumentation/ditypes"
	"github.com/DataDog/datadog-agent/pkg/network/go/bininspect"
	"github.com/DataDog/datadog-agent/pkg/util/log"
)

func GetVariablesAtPC(d *bininspect.DwarfInspector, pc uint64) ([]*ditypes.Parameter, error) {
	var variables []*ditypes.Parameter
	reader := d.DwarfData.Reader()

	for {
		entry, err := reader.Next()
		if err != nil {
			return nil, err
		}
		if entry == nil {
			break
		}

		if entry.Tag == dwarf.TagCompileUnit {
			if err := processCompilationUnit(d, reader, pc, &variables); err != nil {
				return nil, err
			}
		} else {
			reader.SkipChildren()
		}
	}

	return variables, nil
}

func processCompilationUnit(d *bininspect.DwarfInspector, reader *dwarf.Reader, pc uint64, variables *[]*ditypes.Parameter) error {
	for {
		entry, err := reader.Next()
		if err != nil {
			return err
		}
		if entry == nil || entry.Tag == 0 {
			break
		}

		if entry.Tag == dwarf.TagSubprogram {
			if err := processSubprogram(d, reader, entry, pc, variables); err != nil {
				return err
			}
			// children of the function are already processed
			reader.SkipChildren()
		} else {
			reader.SkipChildren()
		}
	}
	return nil
}

func processSubprogram(d *bininspect.DwarfInspector, reader *dwarf.Reader, entry *dwarf.Entry, pc uint64, variables *[]*ditypes.Parameter) error {
	if !entryContainsPC(d, entry, pc) {
		return nil
	}

	log.Debugf("Subprogram %s contains PC %#x", entry.Val(dwarf.AttrName), pc)
	for {
		child, err := reader.Next()
		if err != nil {
			return err
		}
		if child == nil || child.Tag == 0 {
			break
		}

		switch child.Tag {
		case dwarf.TagFormalParameter, dwarf.TagVariable:
			if err := collectVariable(d, child, pc, variables); err != nil {
				log.Infof("Error collecting variable: %v", err)
			}
		case dwarf.TagLexDwarfBlock:
			if err := processLexicalBlock(d, reader, child, pc, variables); err != nil {
				return err
			}
		default:
			reader.SkipChildren()
		}
	}
	return nil
}

func processLexicalBlock(d *bininspect.DwarfInspector, reader *dwarf.Reader, entry *dwarf.Entry, pc uint64, variables *[]*ditypes.Parameter) error {
	if !entryContainsPC(d, entry, pc) {
		reader.SkipChildren()
		return nil
	}

	for {
		child, err := reader.Next()
		if err != nil {
			return err
		}
		if child == nil || child.Tag == 0 {
			break
		}

		switch child.Tag {
		case dwarf.TagFormalParameter, dwarf.TagVariable:
			if err := collectVariable(d, child, pc, variables); err != nil {
				log.Infof("Error collecting variable: %v", err)
			}
		case dwarf.TagLexDwarfBlock:
			if err := processLexicalBlock(d, reader, child, pc, variables); err != nil {
				log.Infof("Error processing lexical block: %v", err)
			}
		default:
			reader.SkipChildren()
		}
	}
	return nil
}

func entryContainsPC(d *bininspect.DwarfInspector, entry *dwarf.Entry, pc uint64) bool {
	lowPCAttr := entry.Val(dwarf.AttrLowpc)
	highPCAttr := entry.Val(dwarf.AttrHighpc)
	rangesAttr := entry.Val(dwarf.AttrRanges)

	if lowPCAttr != nil && highPCAttr != nil {
		log.Debugf("Checking PC range for entry %s: [%#x, %#x]", entry.Val(dwarf.AttrName), lowPCAttr, highPCAttr)
		lowPC := lowPCAttr.(uint64)
		// high_pc can be a relative offset or absolute address
		var highPC uint64
		switch v := highPCAttr.(type) {
		case uint64:
			highPC = v
		case int64:
			highPC = lowPC + uint64(v)
		}

		return pc >= lowPC && pc < highPC
	} else if rangesAttr != nil {
		ranges, err := d.DwarfData.Ranges(entry)
		if err != nil {
			return false
		}
		for _, r := range ranges {
			if pc >= r[0] && pc < r[1] {
				return true
			}
		}
	}

	// if no PC range info, assume it does not include the PC
	log.Debugf("No PC range info for %s", entry.Val(dwarf.AttrName))
	return false
}

func collectVariable(d *bininspect.DwarfInspector, entry *dwarf.Entry, pc uint64, variables *[]*ditypes.Parameter) error {
	nameAttr := entry.Val(dwarf.AttrName)
	if nameAttr == nil {
		return nil // anonymous variable
	}
	varName := nameAttr.(string)

	paramMeta, err := d.GetParameterLocationAtPC(entry, pc)
	if err != nil {
		return fmt.Errorf("failed to get location for var %s: %w", varName, err)
	}

	// get the type attribute and find type entry
	typeAttr := entry.Val(dwarf.AttrType)
	if typeAttr == nil {
		return fmt.Errorf("no type attribute for variable %s", varName)
	}
	typeOffset := typeAttr.(dwarf.Offset)
	typeEntry, err := d.DwarfData.Type(typeOffset)
	if err != nil {
		return fmt.Errorf("error finding type entry for variable %s: %w", varName, err)
	}
	typeName := typeEntry.String()

	varParam, err := convertToParameter(varName, typeName, paramMeta)
	if err != nil {
		return err
	}

	log.Debugf("Found variable %s at PC %#x", varName, pc)
	*variables = append(*variables, varParam)
	return nil
}
