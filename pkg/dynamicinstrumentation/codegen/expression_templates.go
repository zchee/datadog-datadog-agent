// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux_bpf

package codegen

var readRegisterTemplateText = `
// Arg1 = register
// Arg2 = size of element
bpf_printk("Reading from register");

char valueHolder_{{.InstructionID}}[{{.Arg2}}];
bpf_probe_read(&valueHolder_{{.InstructionID}}, {{.Arg2}}, &ctx->DWARF_REGISTER({{.Arg1}}));

for(i = 0; i < {{.Arg2}}; i++){
    bpf_printk("\t%d", valueHolder_{{.InstructionID}}[i]);
    bpf_map_push_elem(&param_stack, valueHolder_{{.InstructionID}}+i, 0);
}
`

var readStackTemplateText = `
// Arg1 = stack offset
// Arg2 = size of element
bpf_printk("Reading from stack");

char valueHolder_{{.InstructionID}}[{{.Arg2}}];
bpf_probe_read(&valueHolder_{{.InstructionID}}, {{.Arg2}}, &ctx->DWARF_STACK_REGISTER+{{.Arg1}});

for(i = 0; i < {{.Arg2}}; i++){
    bpf_printk("\t%d", valueHolder_{{.InstructionID}}[i]);
    bpf_map_push_elem(&param_stack, valueHolder_{{.InstructionID}}+i, 0);
}
`

var popTemplateText = `
// Arg1 = number of bytes to pop
bpf_printk("Popping, printing each character as it's popped");
char valueHolder_{{.InstructionID}};

for(i = {{.Arg1}}-1; i >= 0; i--) {
    bpf_map_pop_elem(&param_stack, &valueHolder_{{.InstructionID}});
    bpf_printk("\t%d", valueHolder_{{.InstructionID}});
    bpf_probe_read(&event->output[outputOffset+i], 1, &valueHolder_{{.InstructionID}});
}
outputOffset += {{.Arg1}};
`

var variablePopTemplateText = `
// No arguments



`

var dereferenceTemplateText = `
// Arg1 = size of value we're reading from the 8 byte address at the top of the stack
bpf_printk("Dereferencing");

__u64 addressHolder_{{.InstructionID}} = 0;
char place_holder_value_{{.InstructionID}} = 0;

// Pop the top 8 elements from the stack, hold in addressHolder_{{.InstructionID}}
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
for(i = 0; i < {{.Arg1}}; i++){
    bpf_map_push_elem(&param_stack, &valueHolder_{{.InstructionID}}[i], 0);
}
`

var variableDereferenceTemplateText = `
// Arg1 = maximum length

bpf_printk("Variable length dereferencing");

// Read the string/slice address
__u64 addressHolder_{{.InstructionID}} = 0;
char place_holder_value_{{.InstructionID}} = 0;

// Pop the top 8 elements from the stack, hold in addressHolder_{{.InstructionID}}
for(i = 0; i < 8; i++) {
    bpf_map_pop_elem(&param_stack, &place_holder_value_{{.InstructionID}});
    addressHolder_{{.InstructionID}} |= (__u64)place_holder_value_{{.InstructionID}} << (8 * (7-i));
}

// Read the string/slice length
__u64 lengthHolder_{{.InstructionID}} = 0;

// Pop the top 8 elements from the stack, hold in lengthHolder_{{.InstructionID}}
for(i = 0; i < 8; i++) {
    bpf_map_pop_elem(&param_stack, &place_holder_value_{{.InstructionID}});
    lengthHolder_{{.InstructionID}} |= (__u64)place_holder_value_{{.InstructionID}} << (8 * (7-i));
}

// Limit size
if (lengthHolder_{{.InstructionID}} > {{.Arg1}}) {
    lengthHolder_{{.InstructionID}} = {{.Arg1}};
}

// Read variable number of bytes from the address that was popped from the stack
char valueHolder_{{.InstructionID}}[lengthHolder_{{.InstructionID}}];
bpf_probe_read_user(valueHolder_{{.InstructionID}}, lengthHolder_{{.InstructionID}}, (void*)addressHolder_{{.InstructionID}});

// Push dereferenced value onto stack
for(i = 0; i < lengthHolder_{{.InstructionID}}; i++){
    bpf_map_push_elem(&param_stack, &valueHolder_{{.InstructionID}}[i], 0);
}

// Push length onto stack
for(i = 0; i < 8; i++) {
	place_holder_value_{{.InstructionID}} = lengthHolder_{{.InstructionID}} >> (8 * (7-i))
    bpf_map_push_elem(&param_stack, &place_holder_value_{{.InstructionID}}, 0);
}
`

var applyOffsetTemplateText = `
// Arg1 = uint value (offset) we're adding to the 8-byte address on top of the stack
bpf_printk("Applying offset");

__u64 addressHolder_{{.InstructionID}} = 0;
char place_holder_value_{{.InstructionID}} = 0;

for(i = 0; i < 8; i++) {
    bpf_map_pop_elem(&param_stack, &place_holder_value_{{.InstructionID}});
    addressHolder_{{.InstructionID}} |= (__u64)place_holder_value_{{.InstructionID}} << (8 * (7-i));
}

// add Arg1 to the converted uint
addressHolder_{{.InstructionID}} += {{.Arg1}};

char valueHolder_{{.InstructionID}};

for(i = 0; i < 8; i++) {
    valueHolder_{{.InstructionID}} = addressHolder_{{.InstructionID}}>>(8*i);
    bpf_map_push_elem(&param_stack, &valueHolder_{{.InstructionID}}, 0);
}
`
