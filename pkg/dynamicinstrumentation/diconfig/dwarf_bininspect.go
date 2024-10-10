package diconfig

import (
	"debug/dwarf"
	"debug/elf"
	"fmt"

	"github.com/DataDog/datadog-agent/pkg/dynamicinstrumentation/ditypes"
	"github.com/DataDog/datadog-agent/pkg/network/go/bininspect"
	"github.com/DataDog/datadog-agent/pkg/network/go/dwarfutils"
	"github.com/DataDog/datadog-agent/pkg/network/go/dwarfutils/locexpr"
	"github.com/go-delve/delve/pkg/dwarf/godwarf"
	"github.com/go-delve/delve/pkg/dwarf/loclist"
	"github.com/kr/pretty"
)

type dwarfInspector struct {
	elf       elfMetadata
	dwarfData *dwarf.Data
}

type elfMetadata struct {
	file *elf.File
	arch GoArch
}

type GoArch string

const (
	// GoArchX86_64 corresponds to x86 64-bit ("amd64")
	GoArchX86_64 GoArch = "amd64"
	// GoArchARM64 corresponds to ARM 64-bit ("arm64")
	GoArchARM64 GoArch = "arm64"
)

func (a *GoArch) PointerSize() uint {
	switch *a {
	case GoArchX86_64:
		return 8
	case GoArchARM64:
		return 8
	default:
		return 0
	}
}

func GetLocation(d *dwarfInspector, funcName, varName string, pc uint64) (*ditypes.Location, error) {
	r := d.dwarfData.Reader()
	for {
		entry, err := r.Next()
		if err != nil {
			return nil, err
		}
		if entry == nil {
			break
		}

		if entry.Tag == dwarf.TagSubprogram {
			nameAttr := entry.Val(dwarf.AttrName)
			if nameAttr != nil && nameAttr.(string) == funcName {
				loc, err := findVariableInFunction(d, r, varName, pc)
				if err != nil {
					fmt.Printf("Did not find variable %s in %s at 0x%x: %v\n", varName, funcName, pc, err)
					return nil, err
				}
				fmt.Printf("Found variable %s in %s at 0x%x\n", varName, funcName, pc)
				pretty.Log(loc)
				return nil, nil
			} else {
				if entry.Children {
					r.SkipChildren()
				}
			}
		}
	}
	return nil, fmt.Errorf("Variable %s not found in function %s", varName, funcName)
}

func findVariableInFunction(d *dwarfInspector, r *dwarf.Reader, varName string, pc uint64) (bininspect.ParameterMetadata, error) {
	for {
		entry, err := r.Next()
		if err != nil {
			return bininspect.ParameterMetadata{}, err
		}
		if entry == nil || entry.Tag == 0 {
			break
		}

		if entry.Tag == dwarf.TagFormalParameter || entry.Tag == dwarf.TagVariable {
			nameAttr := entry.Val(dwarf.AttrName)
			if nameAttr != nil && nameAttr.(string) == varName {
				// Found the variable, now get it's location
				return d.getParameterLocationAtPC(entry, pc)
			}
		}
	}
	return bininspect.ParameterMetadata{}, fmt.Errorf("Variable %s not found", varName)
}

func (d dwarfInspector) getParameterLocationAtPC(parameterDIE *dwarf.Entry, pc uint64) (bininspect.ParameterMetadata, error) {
	typeOffset, ok := parameterDIE.Val(dwarf.AttrType).(dwarf.Offset)
	if !ok {
		return bininspect.ParameterMetadata{}, fmt.Errorf("no type offset attribute in parameter entry")
	}

	// Find the location field on the entry
	locationField := parameterDIE.AttrField(dwarf.AttrLocation)
	if locationField == nil {
		return bininspect.ParameterMetadata{}, fmt.Errorf("no location field in parameter entry")
	}

	typ, err := dwarfutils.NewTypeFinder(d.dwarfData).FindTypeByOffset(typeOffset)
	if err != nil {
		return bininspect.ParameterMetadata{}, fmt.Errorf("could not find parameter type by offset: %w", err)
	}

	// The location field can be one of two things:
	// (See DWARF v4 spec section 2.6)
	// 1. Single location descriptions,
	//    which specifies a location expression as the direct attribute value.
	//    This has a DWARF class of `exprloc`,
	//    and the value is a `[]byte` that can be directly interpreted.
	// 2. Location lists, which gives an index into the loclists section.
	//    This has a DWARF class of `loclistptr`,
	//    which is used to index into the location list
	//    and to get the location expression that corresponds to
	//    the given program counter
	//    (in this case, that is the entry of the function, where we will attach the uprobe).
	var locationExpression []byte
	switch locationField.Class {
	case dwarf.ClassExprLoc:
		if locationValAsBytes, ok := locationField.Val.([]byte); ok {
			locationExpression = locationValAsBytes
		} else {
			return bininspect.ParameterMetadata{}, fmt.Errorf("formal parameter entry contained invalid value for location attribute: locationField=%#v", locationField)
		}
	case dwarf.ClassLocListPtr:
		locationAsLocListIndex, ok := locationField.Val.(int64)
		if !ok {
			return bininspect.ParameterMetadata{}, fmt.Errorf("could not interpret location attribute in formal parameter entry as location list pointer: locationField=%#v", locationField)
		}

		loclistEntry, err := d.getLoclistEntry(locationAsLocListIndex, pc)
		if err != nil {
			return bininspect.ParameterMetadata{}, fmt.Errorf("could not find loclist entry at %#x for PC %#x: %w", locationAsLocListIndex, pc, err)
		}
		locationExpression = loclistEntry.Instr
	default:
		return bininspect.ParameterMetadata{}, fmt.Errorf("unexpected field class on formal parameter's location attribute: locationField=%#v", locationField)
	}

	totalSize := typ.Size()
	pieces, err := locexpr.Exec(locationExpression, totalSize, int(d.elf.arch.PointerSize()))
	if err != nil {
		return bininspect.ParameterMetadata{}, fmt.Errorf("error executing location expression for parameter: %w", err)
	}
	inspectPieces := make([]bininspect.ParameterPiece, len(pieces))
	for i, piece := range pieces {
		inspectPieces[i] = bininspect.ParameterPiece{
			Size:        piece.Size,
			InReg:       piece.InReg,
			StackOffset: piece.StackOffset,
			Register:    piece.Register,
		}
	}
	return bininspect.ParameterMetadata{
		TotalSize: totalSize,
		Kind:      typ.Common().ReflectKind,
		Pieces:    inspectPieces,
	}, nil
}

// getLoclistEntry returns the loclist entry in the loclist
// starting at offset, for address pc.
// Adapted from github.com/go-delve/delve/pkg/proc.(*BinaryInfo).loclistEntry
func (d dwarfInspector) getLoclistEntry(offset int64, pc uint64) (*loclist.Entry, error) {
	debugInfoBytes, err := godwarf.GetDebugSectionElf(d.elf.file, "info")
	if err != nil {
		return nil, err
	}

	compileUnits, err := dwarfutils.LoadCompileUnits(d.dwarfData, debugInfoBytes)
	if err != nil {
		return nil, err
	}

	debugLocBytes, _ := godwarf.GetDebugSectionElf(d.elf.file, "loc")
	loclist2 := loclist.NewDwarf2Reader(debugLocBytes, int(d.elf.arch.PointerSize()))
	debugLoclistBytes, _ := godwarf.GetDebugSectionElf(d.elf.file, "loclists")
	loclist5 := loclist.NewDwarf5Reader(debugLoclistBytes)
	debugAddrBytes, _ := godwarf.GetDebugSectionElf(d.elf.file, "addr")
	debugAddrSection := godwarf.ParseAddr(debugAddrBytes)

	var base uint64
	compileUnit := compileUnits.FindCompileUnit(pc)
	if compileUnit != nil {
		base = compileUnit.LowPC
	}

	var loclist loclist.Reader = loclist2
	var debugAddr *godwarf.DebugAddr
	if compileUnit != nil && compileUnit.Version >= 5 && loclist5 != nil {
		loclist = loclist5
		if addrBase, ok := compileUnit.Entry.Val(dwarf.AttrAddrBase).(int64); ok {
			debugAddr = debugAddrSection.GetSubsection(uint64(addrBase))
		}
	}

	if loclist.Empty() {
		return nil, fmt.Errorf("no loclist found for the given program counter")
	}

	// Use 0x0 as the static base
	var staticBase uint64 = 0x0
	entry, err := loclist.Find(int(offset), staticBase, base, pc, debugAddr)
	if err != nil {
		return nil, fmt.Errorf("error reading loclist section: %w", err)
	}
	if entry != nil {
		return entry, nil
	}

	return nil, fmt.Errorf("no loclist entry found")
}
