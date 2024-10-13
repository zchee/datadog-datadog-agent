package diconfig

import (
	"debug/dwarf"
	"fmt"

	"github.com/DataDog/datadog-agent/pkg/dynamicinstrumentation/ditypes"
	"github.com/DataDog/datadog-agent/pkg/network/go/bininspect"
	"github.com/DataDog/datadog-agent/pkg/util/log"
	"github.com/kr/pretty"
)

func GetParameterAtPC(d *bininspect.DwarfInspector, funcName, varName string, pc uint64) (*ditypes.Parameter, error) {
	r := d.DwarfData.Reader()
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
				param, err := findVariableInFunction(d, r, varName, pc)
				if err != nil {
					return nil, fmt.Errorf("Did not find variable %s in %s at 0x%x: %w", varName, funcName, pc, err)
				}
				log.Debug("Found variable %s in %s at 0x%x\n", varName, funcName, pc)
				log.Debug(pretty.Sprint(param))
				return param, nil
			} else {
				if entry.Children {
					r.SkipChildren()
				}
			}
		}
	}
	return nil, fmt.Errorf("Variable %s not found in function %s", varName, funcName)
}

func findVariableInFunction(d *bininspect.DwarfInspector, r *dwarf.Reader, varName string, pc uint64) (*ditypes.Parameter, error) {
	for {
		// iterate through DWARF entries until we find the variable
		entry, err := r.Next()
		if err != nil {
			return nil, err
		}
		if entry == nil || entry.Tag == 0 {
			break
		}

		if entry.Tag == dwarf.TagFormalParameter || entry.Tag == dwarf.TagVariable {
			nameAttr := entry.Val(dwarf.AttrName)
			if nameAttr != nil && nameAttr.(string) == varName {
				// variable name matched, now get its location at the specified program counter
				paramMeta, err := d.GetParameterLocationAtPC(entry, pc)
				if err != nil {
					return nil, err
				}

				// get the type attribute and find type entry
				typeAttr := entry.Val(dwarf.AttrType)
				if typeAttr == nil {
					return nil, fmt.Errorf("No type attribute for variable %s", varName)
				}
				typeOffset := typeAttr.(dwarf.Offset)
				typeEntry, err := d.DwarfData.Type(typeOffset)
				if err != nil {
					return nil, fmt.Errorf("Error finding type entry for variable %s: %w", varName, err)
				}
				typeName := typeEntry.String()
				return convertToParameter(varName, typeName, paramMeta)
			}
		}
	}
	return nil, fmt.Errorf("No DWARF entry for variable %s", varName)
}

func convertToParameter(varName, typeName string, pm bininspect.ParameterMetadata) (*ditypes.Parameter, error) {
	param := &ditypes.Parameter{
		Name:      varName,
		Type:      typeName,
		TotalSize: pm.TotalSize,
		Kind:      uint(pm.Kind),
		Location: ditypes.Location{
			InReg:       pm.Pieces[0].InReg,
			Register:    pm.Pieces[0].Register,
			StackOffset: pm.Pieces[0].StackOffset,

			NeedsDereference: false,
			PointerOffset:    0,
		},

		// TODO: handle complex types with pieces
		ParameterPieces: []ditypes.Parameter{},
	}

	return param, nil
}
