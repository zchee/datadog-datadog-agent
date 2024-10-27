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

__u64 valueHolder_{{.InstructionID}} = 0;
bpf_probe_read(&valueHolder_{{.InstructionID}}, {{.Arg2}}, &ctx->DWARF_REGISTER({{.Arg1}}));
bpf_map_push_elem(&param_stack, &valueHolder_{{.InstructionID}}, 0);

bpf_printk("Pushed %d", valueHolder_{{.InstructionID}});
`

var readStackTemplateText = `
// Arg1 = stack offset
// Arg2 = size of element
bpf_printk("Reading from stack");

__u64 valueHolder_{{.InstructionID}} = 0;
bpf_probe_read(&valueHolder_{{.InstructionID}}, {{.Arg2}}, &ctx->DWARF_STACK_REGISTER+{{.Arg1}});
bpf_printk("Value: %d", valueHolder_{{.InstructionID}});
bpf_map_push_elem(&param_stack, &valueHolder_{{.InstructionID}}, 0);

bpf_printk("Pushed %d", valueHolder_{{.InstructionID}});
`

var readRegisterValueToOutputTemplateText = `
// Arg1 = register
// Arg2 = size of element
bpf_printk("Reading from register directly to output");
bpf_probe_read(&event->output[outputOffset], {{.Arg2}}, &ctx->DWARF_REGISTER({{.Arg1}}));
outputOffset += {{.Arg2}};
`

var readStackValueToOutputTemplateText = `
// Arg1 = stack offset
// Arg2 = size of element
bpf_printk("Reading from stack directly to output");
bpf_probe_read(&event->output[outputOffset], {{.Arg2}}, &ctx->DWARF_STACK_REGISTER+{{.Arg1}});
outputOffset += {{.Arg2}};
`

var popTemplateText = `
// Arg1 = number of elements (u64) to pop
// Arg2 = size of each element
bpf_printk("Popping, printing each element as it's popped");
__u64 valueHolder_{{.InstructionID}};

for(i = 0; i < {{.Arg1}}; i++) {
    bpf_map_pop_elem(&param_stack, &valueHolder_{{.InstructionID}});
    bpf_printk("\t%d", valueHolder_{{.InstructionID}});
    bpf_probe_read(&event->output[outputOffset+i], 8, &valueHolder_{{.InstructionID}});
    outputOffset += {{.Arg2}};
}
`

var dereferenceTemplateText = `
// Arg1 = size in bytes of value we're reading from the 8 byte address at the top of the stack
bpf_printk("Dereferencing");

__u64 addressHolder_{{.InstructionID}} = 0;
bpf_map_pop_elem(&param_stack, &addressHolder_{{.InstructionID}});

// Read {{.Arg1}} bytes from the address that was popped from the stack

__u64 valueHolder_{{.InstructionID}} = 0;
bpf_probe_read(&valueHolder_{{.InstructionID}}, {{.Arg1}}, (void*)addressHolder_{{.InstructionID}});
bpf_printk("\tRead %d bytes from %x for value %d", {{.Arg1}}, (void*)addressHolder_{{.InstructionID}}, valueHolder_{{.InstructionID}});

__u64 mask_{{.InstructionID}} = ({{.Arg1}} == 8) ? ~0ULL : (1ULL << (8 * {{.Arg1}})) - 1;

__u64 encodedValueHolder_{{.InstructionID}} = valueHolder_{{.InstructionID}} & mask_{{.InstructionID}};
bpf_printk("\tEncoded value %d", encodedValueHolder_{{.InstructionID}});

bpf_map_push_elem(&param_stack, &encodedValueHolder_{{.InstructionID}}, 0);
`

var dereferenceToOutputTemplateText = `
// Arg1 = size in bytes of value we're reading from the 8 byte address at the top of the stack
bpf_printk("Dereferencing");

__u64 addressHolder_{{.InstructionID}} = 0;
bpf_map_pop_elem(&param_stack, &addressHolder_{{.InstructionID}});

// Read {{.Arg1}} bytes from the address that was popped from the stack

__u64 valueHolder_{{.InstructionID}} = 0;
bpf_probe_read(&valueHolder_{{.InstructionID}}, {{.Arg1}}, (void*)addressHolder_{{.InstructionID}});
bpf_printk("\tRead %d bytes from %x for value %d", {{.Arg1}}, (void*)addressHolder_{{.InstructionID}}, valueHolder_{{.InstructionID}});

__u64 mask_{{.InstructionID}} = ({{.Arg1}} == 8) ? ~0ULL : (1ULL << (8 * {{.Arg1}})) - 1;

__u64 encodedValueHolder_{{.InstructionID}} = valueHolder_{{.InstructionID}} & mask_{{.InstructionID}};
bpf_printk("\tEncoded value %d", encodedValueHolder_{{.InstructionID}});

bpf_probe_read(&event->output[outputOffset], {{.Arg1}}, &encodedValueHolder_{{.InstructionID}});
outputOffset += {{.Arg1}};

bpf_probe_read(&event->output[outputOffset], 8, &addressHolder_{{.InstructionID}});
outputOffset += 8;
`

var dereferenceLargeTemplateText = `
// Arg1 = size in bytes of value we're reading from the 8 byte address at the top of the stack
// Arg2 = number of chunks (should be ({{.Arg1}} + 7) / 8)
bpf_printk("Dereferencing");

__u64 addressHolder_{{.InstructionID}} = 0;
bpf_map_pop_elem(&param_stack, &addressHolder_{{.InstructionID}});

for (i = 0; i < {{.Arg2}}; i++) {
    chunk_size = (i == {{.Arg2}} - 1 && {{.Arg1}} % 8 != 0) ? ({{.Arg1}} % 8) : 8;
    bpf_probe_read(&temp_storage[i], {{.Arg1}}, (void*)(addressHolder_{{.InstructionID}} + (i * 8)));
}

// Mask the last chunk if {{.Arg1}} is not a multiple of 8
if ({{.Arg1}} % 8 != 0) {
    __u64 mask = (1ULL << (8 * ({{.Arg1}} % 8))) - 1;
    temp_storage[{{.Arg2}} - 1] &= mask;
}

for (int i = 0; i < {{.Arg2}}; i++) {
    bpf_map_push_elem(&param_stack, &temp_storage[i], 0);
}

// zero out shared array
bpf_probe_read(temp_storage, {{.Arg1}}*{{.Arg2}}, zero_string);
`

var dereferenceLargeToOutputTemplateText = `
// Arg1 = size in bytes of value we're reading from the 8 byte address at the top of the stack
// Arg2 = number of chunks (should be ({{.Arg1}} + 7) / 8)
bpf_printk("Dereferencing");

__u64 addressHolder_{{.InstructionID}} = 0;
bpf_map_pop_elem(&param_stack, &addressHolder_{{.InstructionID}});

for (i = 0; i < {{.Arg2}}; i++) {
    chunk_size = (i == {{.Arg2}} - 1 && {{.Arg1}} % 8 != 0) ? ({{.Arg1}} % 8) : 8;
    bpf_probe_read(&temp_storage[i], {{.Arg1}}, (void*)(addressHolder_{{.InstructionID}} + (i * 8)));
}

// Mask the last chunk if {{.Arg1}} is not a multiple of 8
if ({{.Arg1}} % 8 != 0) {
    __u64 mask = (1ULL << (8 * ({{.Arg1}} % 8))) - 1;
    temp_storage[{{.Arg2}} - 1] &= mask;
}

for (int i = 0; i < {{.Arg2}}; i++) {
    bpf_probe_read(&event->output[outputOffset], 8, &temp_storage[i]);
    outputOffset += 8;
}

// zero out shared array
bpf_probe_read(temp_storage, {{.Arg1}}*{{.Arg2}}, zero_string);
`

var applyOffsetTemplateText = `
// Arg1 = uint value (offset) we're adding to the 8-byte address on top of the stack
bpf_printk("Applying offset");

__u64 addressHolder_{{.InstructionID}} = 0;
bpf_map_pop_elem(&param_stack, &addressHolder_{{.InstructionID}});
addressHolder_{{.InstructionID}} += {{.Arg1}};
bpf_map_push_elem(&param_stack, &addressHolder_{{.InstructionID}}, 0);
`

var variablePopTemplateText = `
`

var variableDereferenceTemplateText = `

`

var variableDereferenceToOutputTemplateText = `
`
