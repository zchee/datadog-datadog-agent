// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux_bpf

package codegen

var readRegisterTemplateText = `
// Arg1 = reigster
// Arg2 = size of element
bpf_printk("Reading");

char valueHolder_{{.InstructionID}}[{{.Arg2}}];
bpf_probe_read(&valueHolder_{{.InstructionID}}, {{.Arg2}}, &ctx->DWARF_REGISTER({{.Arg1}}));

#pragma unroll
for(i = 0; i < {{.Arg2}}; i++){
	bpf_printk("\t%d", valueHolder_{{.InstructionID}}[i]);
	bpf_map_push_elem(&param_stack, valueHolder_{{.InstructionID}}+i, 0);
}
`

var popTemplateText = `
// Arg1 = number of bytes to pop
bpf_printk("Popping, printing each character as it's popped");
char valueHolder_{{.InstructionID}};

#pragma unroll
for(i = {{.Arg1}}-1; i >= 0; i--) {
	bpf_map_pop_elem(&param_stack, &valueHolder_{{.InstructionID}});
	bpf_printk("\t%d", valueHolder_{{.InstructionID}});
	bpf_probe_read(&event->output[outputOffset+i], 1, &valueHolder_{{.InstructionID}});
}
outputOffset += {{.Arg1}};
`

var dereferenceTemplateText = `
// Arg1 = size of value we're reading from the 8 byte address at the top of the stack
bpf_printk("Dereferencing");

__u64 addressHolder_{{.InstructionID}} = 0;
char place_holder_value_{{.InstructionID}} = 0;

// Pop the top 8 elements from the stack, hold in addressHolder_{{.InstructionID}}
#pragma unroll
for(i = 0; i < 8; i++) {
	bpf_map_pop_elem(&param_stack, &place_holder_value_{{.InstructionID}});
	bpf_printk("\tchar: %d", place_holder_value_{{.InstructionID}});
	addressHolder_{{.InstructionID}} |= (__u64)place_holder_value_{{.InstructionID}} << (8 * (7-i));
	bpf_printk("\tAddr: 0x%x", addressHolder_{{.InstructionID}});
}

// Read {{.Arg1}} bytes from the address that was popped from the stack into valueHolder_{{.InstructionID}}[{{.Arg1}}]
char valueHolder_{{.InstructionID}}[{{.Arg1}}];
bpf_probe_read_user(valueHolder_{{.InstructionID}}, {{.Arg1}}, (void*)addressHolder_{{.InstructionID}});

// Push dereferenced value onto stack
#pragma unroll
for(i = {{.Arg1}}; i >= 0; i--){
	bpf_map_push_elem(&param_stack, &valueHolder_{{.InstructionID}}[i], 0);
}
`

var applyOffsetTemplateText = `
// Arg1 = uint value (offset) we're adding to the 8-byte address on top of the stack

char valueHolder_{{.InstructionID}}[8];

#pragma unroll
for(i = 7; i >= 0; i--) {
	bpf_map_pop_elem(&param_stack, valueHolder_{{.InstructionID}}+i);
}

// convert the array 'valueHolder_{{.InstructionID}}' to uint
__u64 uintRepresentationOfAddress{{.InstructionID}} = 0;

#pragma unroll
for (int i = 0; i < 8; i++) {
	uintRepresentationOfAddress{{.InstructionID}} |= (__u64)valueHolder_{{.InstructionID}}[i] << (8 * (7 - i));
}

// add Arg1 to the converted uint
uintRepresentationOfAddress{{.InstructionID}} = uintRepresentationOfAddress{{.InstructionID}} + {{.Arg1}};

// convert the result to an array of chars
#pragma unroll
for (int i = 0; i < 8; i++) {
	valueHolder_{{.InstructionID}}[7 - i] = (char)({{.Arg1}} >> (8 * i));
}

// push the array back onto the stack
#pragma unroll
for(i = 0; i < 8; i++){
	bpf_map_push_elem(&param_stack, valueHolder_{{.InstructionID}}+i, 0);
}
`
