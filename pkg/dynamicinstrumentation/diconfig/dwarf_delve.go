package diconfig

// func processLocationAttribute2(entry *dwarf.Entry, locAttr any, dwarfData *dwarf.Data, pc uint64, frameBaseExpr []byte, loclistData []byte) (*ditypes.Location, error) {
// 	switch locAttr.(type) {
// 	case []byte:
// 		// Single location expression
// 		locExpr := locAttr
// 		return evaluateLocationExpression(locExpr, frameBaseExpr)
// 	case int64:
// 		// Offset into the location lists
// 		offset := locAttr.(dwarf.Offset)
// 		ptrSize := int(getPointerSize(dwarfData))
// 		byteOrder := dwarfData.Reader().ByteOrder()
// 		locList, err := loclist.Parse(loclistData, offset, byteOrder, ptrSize)
// 		if err != nil {
// 			return nil, err
// 		}
// 		// Find the location list entry that matches the pc
// 		for _, entry := range locList {
// 			if entry.LowPC <= pc && pc < entry.HighPC {
// 				locExpr := entry.Insn
// 				frameBase, err := evaluateFrameBase(frameBaseExpr)
// 				if err != nil {
// 					return nil, err
// 				}
// 				return evaluateLocationExpressionWithFrameBase(locExpr, frameBase, ptrSize)
// 			}
// 		}
// 		return nil, fmt.Errorf("No location expression found for pc 0x%x", pc)
// 	default:
// 		return nil, fmt.Errorf("Unsupported location attribute class: %v", locAttr.Class)
// 	}
// }

// func processLocationAttribute3(
// 	entry *dwarf.Entry,
// 	locAttr *dwarf.AttrField,
// 	dwarfData *dwarf.Data,
// 	pc uint64,
// 	frameBaseExpr []byte,
// 	loclistData []byte,
// ) (*Location, error) {
// 	ptrSize := int(getPointerSize(dwarfData))
// 	switch locAttr.Class {
// 	case dwarf.ClassExprLoc:
// 		// Single location expression
// 		locExpr := locAttr.Val.([]byte)
// 		return evaluateLocationExpression(locExpr, frameBaseExpr)
// 	case dwarf.ClassLocListPtr:
// 		// Offset into the location lists (DWARF v2 and v3)
// 		offset := dwarf.Offset(locAttr.Val.(int64))
// 		// Initialize the DWARF2Reader
// 		locListReader := loclist.NewDwarf2Reader(loclistData, ptrSize)
// 		// Read the location list entries
// 		locEntries, err := locListReader.Find(int(offset))
// 		if err != nil {
// 			return nil, fmt.Errorf("Error reading location list at offset %d: %v", offset, err)
// 		}
// 		// Iterate over location list entries to find the matching one
// 		for _, locEntry := range locEntries {
// 			if locEntry.BaseAddress == nil {
// 				// Update base address if present
// 				continue
// 			}
// 			if locEntry.Start <= pc && pc < locEntry.End {
// 				locExpr := locEntry.Instructions
// 				// Evaluate frame base if necessary
// 				frameBase, err := evaluateFrameBase(frameBaseExpr)
// 				if err != nil {
// 					return nil, err
// 				}
// 				return evaluateLocationExpressionWithFrameBase(locExpr, frameBase)
// 			}
// 		}
// 		return nil, fmt.Errorf("No location expression found for pc 0x%x", pc)
// 	default:
// 		return nil, fmt.Errorf("Unsupported location attribute class: %v", locAttr.Class)
// 	}
// }

// func evaluateFrameBase(expr []byte) (int64, error) {
// 	// Evaluate the frame base expression
// 	// For simplicity, we assume frame base is zero or you can implement proper evaluation
// 	return 0, nil
// }

// func evaluateLocationExpressionWithFrameBase(expr []byte, frameBase int64, ptrSize int) (*ditypes.Location, error) {
// 	// Use Delve's op package to evaluate the location expression
// 	op.PrettyPrint(expr)
// 	regs := op.DwarfRegisters{} // Implement this interface based on your context
// 	addr, pieces, err := op.ExecuteStackProgram(&regs, expr, frameBase, ptrSize)
// 	if addr != 0 {
// 		return nil, fmt.Errorf("Non-zero address after evaluating location expression")
// 	}
// 	if err != nil {
// 		return nil, err
// 	}
// 	if len(pieces) == 0 {
// 		return nil, fmt.Errorf("Empty stack after evaluating location expression")
// 	}
// 	address := stack[len(stack)-1]
// 	// Interpret the address based on your needs
// 	return &ditypes.Location{
// 		InReg:            false,
// 		StackOffset:      int64(address),
// 		NeedsDereference: false,
// 	}, nil
// }
