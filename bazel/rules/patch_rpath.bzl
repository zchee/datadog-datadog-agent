def _patch_or_copy(ctx, src, dst):
    args = ctx.actions.args()
    args.add(ctx.executable._patcher)
    args.add_joined("--set-rpath", ctx.attr.rpaths, join_with = ":")
    args.add("--output", dst)
    args.add(src)

    # patchelf --set-rpath /opt/my-libs/lib:/other-libs my-program
    ctx.actions.run_shell(
        mnemonic = "PatchelfOrCopy",
        # If patchelf fails we just copy src to dst
        command = "\"$@\" || cp -rf \"$6\" \"$5\"",
        arguments = [args],
        inputs = [ctx.executable._patcher, src],
        outputs = [dst],
    )


def _patch_or_copy_directory(ctx, src, dst):
    args = ctx.actions.args()
    args.add(ctx.executable._patcher)
    args.add(src.path)
    args.add(dst.dirname)
    args.add_joined("--set-rpath", ctx.attr.rpaths, join_with = ":")

    ctx.actions.run_shell(
        mnemonic = "PatchelfOrCopyDir",
        # We copy files over first, then apply patchelf where possible on top of the copied files
        # That's the simplest way to apply patchelf recursively while maintaining the
        # original folder structure,
        # but it requires being careful that we make copies of the files and not the links,
        # and adding write permissions
        command = """
        cp -rfL "$2" "$3"
        find "$3" -not -type d \
        -exec chmod 664 {} \\; \
        -exec "$1" "$4" "$5" {} \\;
        """,
        arguments = [args],
        inputs = [ctx.executable._patcher, src],
        outputs = [dst],
    )


def _patch_rpath_impl(ctx):
    inputs = []
    outputs = []
    for input in ctx.files.deps:
        inputs.append(input)
        if input.is_directory:
            output = ctx.actions.declare_directory("patched/%s" % input.short_path)
            outputs.append(output)
            _patch_or_copy_directory(ctx, input, output)
        else:
            output = ctx.actions.declare_file("patched/%s" % input.short_path)
            outputs.append(output)
            _patch_or_copy(ctx, input, output)

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
