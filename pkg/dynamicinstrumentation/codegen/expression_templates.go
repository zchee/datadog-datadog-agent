// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux_bpf

package codegen

var readRegisterTemplateText = `
// Arg1 = reigster
// Arg2 = size of element

char valueHolder_{{.InstructionID}}[{{.Arg2}}];
bpf_probe_read(&valueHolder_{{.InstructionID}}, {{.Arg2}}, &ctx->DWARF_REGISTER({{.Arg1}}));

#pragma unroll
for(i = 0; i < {{.Arg2}}; i++){
	bpf_map_push_elem(&param_stack, valueHolder_{{.InstructionID}}+i, 0);
}
`

var popTemplateText = `
// Arg1 = number of bytes to pop

char valueHolder_{{.InstructionID}};

#pragma unroll
for(i = {{.Arg1}}-1; i >= 0; i--){
	bpf_map_pop_elem(&param_stack, &valueHolder_{{.InstructionID}});
	bpf_probe_read(&event->output[outputOffset+i], 1, &valueHolder_{{.InstructionID}});
}
outputOffset += {{.Arg1}};
`
