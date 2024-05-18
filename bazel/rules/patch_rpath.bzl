def _patch_rpath_impl(ctx):
    inputs = ctx.files.deps
    outputs = [ctx.actions.declare_file("patched/%s" % f.short_path) for f in ctx.files.deps]

    # patchelf --set-rpath /opt/my-libs/lib:/other-libs my-program
    for input, output in zip(inputs, outputs):
        args = ctx.actions.args()
        args.add_joined("--set-rpath", ctx.attr.rpaths, join_with = ":")
        args.add("--output", output)
        args.add(input)
        ctx.actions.run(
            mnemonic = "PatchRPath",
            executable = ctx.executable._patcher,
            arguments = [args],
            inputs = [input],
            outputs = [output],
        )

    return DefaultInfo(files = depset(outputs))


patch_rpath = rule(
    implementation = _patch_rpath_impl,
    attrs = {
        "deps": attr.label_list(allow_files=True),
        "rpaths": attr.string_list(),
        "_patcher": attr.label(
            default = Label("@patchelf//:patchelf"),
            allow_single_file = True,
            executable = True,
            cfg = "exec",
        ),
    },
)
