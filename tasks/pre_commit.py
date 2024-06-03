import os
import re
import socket
import sys

from invoke import task
from invoke.exceptions import Exit

from tasks.libs.common.color import color_message
from tasks.libs.common.git import get_staged_files
from tasks.tools import clang_format
from tasks.tools.clang_format import ExitStatus

DEFAULT_PRE_COMMIT_CONFIG = ".pre-commit-config.yaml"
DEVA_PRE_COMMIT_CONFIG = ".pre-commit-config-deva.yaml"


def update_pyapp_file() -> str:
    with open(DEFAULT_PRE_COMMIT_CONFIG) as file:
        data = file.read()
        for cmd in ('invoke', 'inv'):
            data = data.replace(f"entry: '{cmd}", "entry: 'deva")
    with open(DEVA_PRE_COMMIT_CONFIG, 'w') as file:
        file.write(data)
    return DEVA_PRE_COMMIT_CONFIG


@task
def check_winclang_format(ctx):
    if os.name != 'nt':  # Don't run on Linux
        return

    def find_clang_format(search_dirs):
        for search_dir in search_dirs:
            for root, _, files in os.walk(search_dir):
                for basename in files:
                    if basename == 'clang-format.exe':
                        return os.path.join(root, basename)

    clang_format_path = os.environ.get('CLANG_FORMAT_PATH')
    if clang_format_path is None:
        search_dirs = ['C:/Program Files/Microsoft Visual Studio', 'C:/Program Files (x86)/Microsoft Visual Studio']
        clang_format_path = find_clang_format(search_dirs)

    print(clang_format_path)

    ctx.run(f'"{clang_format_path}" --dry-run --Werror {",".join(get_staged_files(ctx))}')


@task
def check_set_x(ctx):
    # Select only relevant files
    files = [
        path
        for path in get_staged_files(ctx)
        if path.endswith(".sh")
        or path.endswith("Dockerfile")
        or path.endswith(".yml")
        or (path.endswith(".yaml") and not path.startswith(".pre-commit-config"))
    ]

    errors = []
    for file in files:
        with open(file) as f:
            for nb, line in enumerate(f):
                if re.search(r"set( +-[^ ])* +-[^ ]*(x|( +xtrace))", line):
                    errors.append(
                        f"{color_message(file, 'magenta')}:{color_message(nb + 1, 'green')}: {color_message(line.strip(), 'red')}"
                    )

    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        print(color_message('error:', 'red'), 'No shell script should use "set -x"', file=sys.stderr)
        raise Exit(code=1)


@task
def check_clang_format(ctx):
    files = [
        file
        for file in get_staged_files(ctx)
        if (
            re.match(r"^pkg/(ebpf|network|security)/.*\.(c|h)$", file)
            and not re.match(
                "^pkg/ebpf/(c/bpf_endian|c/bpf_helpers|compiler/clang-stdarg).h$",
                file,
            )
        )
    ]

    if files:
        res = clang_format.run(files)
        if res != ExitStatus.SUCCESS:
            raise Exit(code=res)


@task
def check_gitlab_access(_, gitlab_url="gitlab.ddbuild.io", gitlab_port=443, max_ip_tries=4, per_ip_timeout=1):
    """
    Check if the user has access to Gitlab behind Appgate.
    AWS is scaling Load Balancers as needed. When trying to connect to Gitlab with a requests.get(), you'll test each ip address with a timeout of 1 second.
    This means that you'll wait at least n seconds for n addresses to timeout, slowing down the hook by a lot.
    That's why we're limiting the calls to 4 (max_ip_tries) to avoid having a timeout >4s slowing down the hook.
    """
    all_timed_out = True
    gitlab_ip_addresses = socket.getaddrinfo(gitlab_url, gitlab_port, socket.AF_UNSPEC, socket.SOCK_STREAM)[
        :max_ip_tries
    ]
    for res in gitlab_ip_addresses:
        af, socktype, proto, _, sa = res
        try:
            with socket.socket(af, socktype, proto) as sock:
                sock.settimeout(per_ip_timeout)
                sock.connect(sa)
            return
        except TimeoutError:
            print(color_message(f"Connection to {sa[0]}:{sa[1]} timed out.", color="orange"))
        except Exception as e:
            all_timed_out = False
            print(color_message(f"Connection to {sa[0]}:{sa[1]} failed:\n{e}", color="orange"))
    if all_timed_out:
        raise Exit(
            color_message(f"\nConnections to {gitlab_url} all timed out. Are you connected to Appgate?", color="red"),
            code=1,
        )
