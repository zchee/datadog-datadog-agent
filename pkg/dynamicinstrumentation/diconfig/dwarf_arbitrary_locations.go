package diconfig

import (
	"bytes"
	"debug/dwarf"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/DataDog/datadog-agent/pkg/dynamicinstrumentation/ditypes"
	"github.com/DataDog/datadog-agent/pkg/network/go/dwarfutils/locexpr"
	"github.com/kr/pretty"
)

func GetLocation(dwarfData *dwarf.Data, locListData []byte, funcName, varName string, pc uint64) (*ditypes.Location, error) {
	r := dwarfData.Reader()
	for {
		entry, err := r.Next()
		if err != nil {
			return nil, err
		}
		if entry == nil {
			break // End of entries
		}

		if entry.Tag == dwarf.TagSubprogram {
			nameAttr := entry.Val(dwarf.AttrName)
			if nameAttr != nil && nameAttr.(string) == funcName {
				// Found the function entry
				// Now get its DW_AT_frame_base if any
				frameBaseAttr := entry.Val(dwarf.AttrFrameBase)
				var frameBaseExpr []byte
				if frameBaseAttr != nil {
					switch v := frameBaseAttr.(type) {
					case []byte:
						frameBaseExpr = v
					default:
						// Handle other possible types if necessary
					}
				}
				fmt.Println("Found frame base attr")
				pretty.Log(frameBaseExpr)
				// Now process its children to find the variable
				loc, err := findVariableInFunction(r, varName, pc, dwarfData, locListData, frameBaseExpr)
				if err != nil {
					return nil, err
				}
				return loc, nil
			} else {
				// Skip children of functions we're not interested in
				if entry.Children {
					r.SkipChildren()
				}
			}
		}
	}
	return nil, fmt.Errorf("Variable %s not found in function %s", varName, funcName)
}

func findVariableInFunction(r *dwarf.Reader, varName string, pc uint64, dwarfData *dwarf.Data, locListData, frameBaseExpr []byte) (*ditypes.Location, error) {
	for {
		entry, err := r.Next()
		fmt.Println("Found variable entry")
		pretty.Log(entry)
		if err != nil {
			return nil, err
		}
		if entry == nil || entry.Tag == 0 {
			break // End of children
		}
		// Process the entries
		if entry.Tag == dwarf.TagFormalParameter || entry.Tag == dwarf.TagVariable {
			nameAttr := entry.Val(dwarf.AttrName)
			if nameAttr != nil && nameAttr.(string) == varName {
				// Found the variable
				// Now get its location
				locAttr := entry.Val(dwarf.AttrLocation)
				if locAttr != nil {
					// The location attribute can be a location expression or a location list
					// Need to process it
					fmt.Println("Found location attribute")
					pretty.Log(locAttr)

					loc, err := processLocationAttribute(locAttr, dwarfData, locListData, pc, frameBaseExpr)
					if err != nil {
						return nil, err
					}
					return loc, nil
				}
			}
		}
		if entry.Children {
			// Skip nested scopes for this example
			r.SkipChildren()
		}
	}
	return nil, fmt.Errorf("Variable %s not found", varName)
}

func processLocationAttribute(locAttr interface{}, dwarfData *dwarf.Data, locListData []byte, pc uint64, frameBaseExpr []byte) (*ditypes.Location, error) {
	switch loc := locAttr.(type) {
	case []byte:
		// Single location expression
		locExpr := loc
		// Evaluate the expression
		pretty.Log(locExpr)
		return nil, nil
	case int64:
		// This is an offset into the location lists
		// Parse the location lists from .debug_loc
		addrSize := int(getPointerSize(dwarfData))
		locExpr, err := readLocationList(locListData, uint64(loc), addrSize, pc)

		if err != nil {
			return nil, err
		}

		// Evaluate the location expression
		fmt.Println("Found location expression")
		fmt.Println(locexpr.Format(locExpr))
		return nil, nil
	default:
		return nil, fmt.Errorf("Unsupported location attribute type: %T", locAttr)
	}
}

func getPointerSize(d *dwarf.Data) byte {
	// Inspect the DWARF Data to infer pointer size
	// This is a simplified approach and may need adjustments for complex binaries.

	// Example: Check for presence of 64-bit addresses
	// This is heuristic; a more robust method may be required.

	// Attempt to find a DWARF type that uses 64-bit addresses
	r := d.Reader()
	for {
		entry, err := r.Next()
		if err != nil {
			break
		}
		if entry == nil {
			break
		}
		if entry.Tag == dwarf.TagPointerType {
			// Assuming the pointer size is consistent
			// Here we check the attribute for Data Bitness
			addrAttr := entry.AttrField(dwarf.AttrByteSize)
			if addrAttr != nil {
				return byte(addrAttr.Val.(int))
			}
		}
	}

	// Default to 8 bytes (64-bit) if not determinable
	return 8
}

func getByteOrder(d *dwarf.Data) binary.ByteOrder {
	r := d.Reader()
	return r.ByteOrder()
}

func readLocationList(loclistData []byte, offset uint64, addrSize int, pc uint64) ([]byte, error) {
	reader := bytes.NewReader(loclistData[offset:])
	baseAddress := uint64(0)
	for {
		// Read begin address
		beginRaw, err := readUint(reader, addrSize)
		if err != nil {
			return nil, err
		}
		// Read end address
		endRaw, err := readUint(reader, addrSize)
		if err != nil {
			return nil, err
		}
		if beginRaw == 0 && endRaw == 0 {
			// End of list marker
			break
		}
		if (addrSize == 4 && beginRaw == 0xFFFFFFFF) || (addrSize == 8 && beginRaw == 0xFFFFFFFFFFFFFFFF) {
			// Base address selection entry
			baseAddress = endRaw
			continue
		}
		// Read length of location expression
		var length uint16
		if err := binary.Read(reader, binary.LittleEndian, &length); err != nil {
			return nil, err
		}
		// Read location expression
		locExpr := make([]byte, length)
		if _, err := io.ReadFull(reader, locExpr); err != nil {
			return nil, err
		}
		// Calculate actual addresses
		beginAddr := beginRaw + baseAddress
		endAddr := endRaw + baseAddress
		// Check if pc falls within this range
		if pc >= beginAddr && pc < endAddr {
			// We have found the right location expression
			return locExpr, nil
		}
	}
	// If we reach here, pc not found in any range
	return nil, fmt.Errorf("No location expression found for pc 0x%x", pc)
}

func readUint(reader io.Reader, nbytes int) (uint64, error) {
	buf := make([]byte, nbytes)
	if _, err := io.ReadFull(reader, buf); err != nil {
		return 0, err
	}
	var val uint64
	for i := 0; i < nbytes; i++ {
		val |= uint64(buf[i]) << (8 * i)
	}
	return val, nil
}

// func evaluateLocationExpression(expr []byte, frameBaseExpr []byte) (*Location, error) {
// 	// Evaluate the frame base expression if present
// 	frameBase := int64(0)
// 	if len(frameBaseExpr) > 0 {
// 		// For simplicity, we assume frame base evaluates to zero
// 		// In practice, you would need to evaluate frameBaseExpr properly
// 		fbLoc, err := evaluateSimpleExpression(frameBaseExpr)
// 		if err != nil {
// 			return nil, err
// 		}
// 		if fbLoc != nil {
// 			frameBase = fbLoc.StackOffset
// 		}
// 	}

// 	// Now evaluate the variable's location expression
// 	return evaluateSimpleExpressionWithFrameBase(expr, frameBase)
// }

// func evaluateSimpleExpressionWithFrameBase(expr []byte, frameBase int64) (*Location, error) {
// 	// Simple stack-based evaluation
// 	stack := []int64{}
// 	reader := bytes.NewReader(expr)
// 	for {
// 		opcodeByte, err := reader.ReadByte()
// 		if err == io.EOF {
// 			break
// 		}
// 		if err != nil {
// 			return nil, err
// 		}
// 		opcode := dwarf.Op(opcodeByte)
// 		switch opcode {
// 		case dwarf.OpFbreg:
// 			offset, err := readSLEB128(reader)
// 			if err != nil {
// 				return nil, err
// 			}
// 			// The address is frame_base + offset
// 			addr := frameBase + offset
// 			return &Location{
// 				InReg:            false,
// 				StackOffset:      addr,
// 				NeedsDereference: false,
// 			}, nil
// 		case dwarf.OpBreg0, dwarf.OpBreg1, dwarf.OpBreg2, dwarf.OpBreg3, dwarf.OpBreg4,
// 			dwarf.OpBreg5, dwarf.OpBreg6, dwarf.OpBreg7, dwarf.OpBreg8, dwarf.OpBreg9,
// 			dwarf.OpBreg10, dwarf.OpBreg11, dwarf.OpBreg12, dwarf.OpBreg13, dwarf.OpBreg14,
// 			dwarf.OpBreg15, dwarf.OpBreg16, dwarf.OpBreg17, dwarf.OpBreg18, dwarf.OpBreg19,
// 			dwarf.OpBreg20, dwarf.OpBreg21, dwarf.OpBreg22, dwarf.OpBreg23, dwarf.OpBreg24,
// 			dwarf.OpBreg25, dwarf.OpBreg26, dwarf.OpBreg27, dwarf.OpBreg28, dwarf.OpBreg29,
// 			dwarf.OpBreg30, dwarf.OpBreg31:
// 			reg := int(opcode - dwarf.OpBreg0)
// 			offset, err := readSLEB128(reader)
// 			if err != nil {
// 				return nil, err
// 			}
// 			// Location is at register 'reg' plus offset 'offset'
// 			return &Location{
// 				InReg:            true,
// 				StackOffset:      offset,
// 				Register:         reg,
// 				NeedsDereference: true,
// 			}, nil
// 		case dwarf.OpReg0, dwarf.OpReg1, dwarf.OpReg2, dwarf.OpReg3, dwarf.OpReg4, dwarf.OpReg5,
// 			dwarf.OpReg6, dwarf.OpReg7, dwarf.OpReg8, dwarf.OpReg9, dwarf.OpReg10, dwarf.OpReg11,
// 			dwarf.OpReg12, dwarf.OpReg13, dwarf.OpReg14, dwarf.OpReg15, dwarf.OpReg16, dwarf.OpReg17,
// 			dwarf.OpReg18, dwarf.OpReg19, dwarf.OpReg20, dwarf.OpReg21, dwarf.OpReg22, dwarf.OpReg23,
// 			dwarf.OpReg24, dwarf.OpReg25, dwarf.OpReg26, dwarf.OpReg27, dwarf.OpReg28, dwarf.OpReg29,
// 			dwarf.OpReg30, dwarf.OpReg31:
// 			reg := int(opcode - dwarf.OpReg0)
// 			return &Location{
// 				InReg:            true,
// 				StackOffset:      0,
// 				Register:         reg,
// 				NeedsDereference: false,
// 			}, nil
// 		case dwarf.OpAddr:
// 			addr, err := readAddress(reader)
// 			if err != nil {
// 				return nil, err
// 			}
// 			return &Location{
// 				InReg:            false,
// 				StackOffset:      int64(addr),
// 				NeedsDereference: false,
// 			}, nil
// 		case dwarf.OpConstu:
// 			val, err := readULEB128(reader)
// 			if err != nil {
// 				return nil, err
// 			}
// 			stack = append(stack, int64(val))
// 		case dwarf.OpConsts:
// 			val, err := readSLEB128(reader)
// 			if err != nil {
// 				return nil, err
// 			}
// 			stack = append(stack, val)
// 		// Add support for other opcodes as needed
// 		default:
// 			// For simplicity, unhandled opcodes are not supported
// 			return nil, fmt.Errorf("Unhandled opcode: %v", opcode)
// 		}
// 	}
// 	if len(stack) > 0 {
// 		// Assume top of stack is the address
// 		addr := stack[len(stack)-1]
// 		return &Location{
// 			InReg:            false,
// 			StackOffset:      addr,
// 			NeedsDereference: false,
// 		}, nil
// 	}
// 	return nil, fmt.Errorf("Empty location expression")
// }

// // Helper functions to read data from the expression

// func readAddress(reader io.Reader) (uint64, error) {
// 	// Assuming 8-byte addresses (64-bit)
// 	return readUint(reader, 8)
// }

// func readUint(reader io.Reader, nbytes int) (uint64, error) {
// 	buf := make([]byte, nbytes)
// 	_, err := io.ReadFull(reader, buf)
// 	if err != nil {
// 		return 0, err
// 	}
// 	var val uint64
// 	for i := 0; i < nbytes; i++ {
// 		val |= uint64(buf[i]) << (8 * i)
// 	}
// 	return val, nil
// }

// func readSLEB128(reader io.ByteReader) (int64, error) {
// 	var result int64
// 	var shift uint
// 	var size uint
// 	for {
// 		b, err := reader.ReadByte()
// 		if err != nil {
// 			return 0, err
// 		}
// 		size += 7
// 		result |= int64(b&0x7F) << shift
// 		shift += 7
// 		if (b & 0x80) == 0 {
// 			break
// 		}
// 	}
// 	// Sign bit of byte is second high-order bit (0x40)
// 	if shift < 64 && (b&0x40) != 0 {
// 		result |= -(1 << shift)
// 	}
// 	return result, nil
// }

// func readULEB128(reader io.ByteReader) (uint64, error) {
// 	var result uint64
// 	var shift uint
// 	for {
// 		b, err := reader.ReadByte()
// 		if err != nil {
// 			return 0, err
// 		}
// 		result |= uint64(b&0x7F) << shift
// 		shift += 7
// 		if (b & 0x80) == 0 {
// 			break
// 		}
// 	}
// 	return result, nil
// }

// // For simplicity, evaluateSimpleExpression assumes frame base is zero
// func evaluateSimpleExpression(expr []byte) (*Location, error) {
// 	return evaluateSimpleExpressionWithFrameBase(expr, 0)
// }
