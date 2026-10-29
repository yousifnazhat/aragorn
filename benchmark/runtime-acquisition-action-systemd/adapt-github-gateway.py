"""Apply the measured P3.8b systemd/Docker fixture adaptation."""

from __future__ import annotations

import ast
import hashlib
import sys
from pathlib import Path

_PREIMAGE = "21e3a74cb0927d1a160b089797cc169e1d1bfc8c68b7a2b5005904ee7aabe07c"
_POSTIMAGE = "b31305c4555607a19a54a3ef08a61a243fd60ab1b5cacb38b1b04569ec3cac56"
_REPLACEMENTS = (
    (
        '_ISOLATED_ENTRYPOINT = """\\\nimport errno\nimport os\nimport resource\n',
        '_ISOLATED_ENTRYPOINT = """\\\nimport errno\nimport os\nimport re\nimport resource\n',
    ),
    (
        (
            "    if (\n"
            "        len(cgroup_entry) > 4096\n"
            '        or not cgroup_entry.endswith("\\\\n")\n'
            '        or not cgroup_entry.startswith("0::/system.slice/aragorn-gateway-")\n'
            '        or not cgroup_entry.endswith(".service\\\\n")\n'
            "    ):\n"
            "        raise SystemExit(70)\n"
        ),
        (
            "    if (\n"
            "        len(cgroup_entry) > 4096\n"
            "        or re.fullmatch(\n"
            '            r"0::/docker/[0-9a-f]{64}/system[.]slice/"\n'
            '            r"aragorn-gateway-[0-9a-f]{24}[.]service\\\\n",\n'
            "            cgroup_entry,\n"
            "        )\n"
            "        is None\n"
            "    ):\n"
            "        raise SystemExit(70)\n"
        ),
    ),
    (
        ") -> _ProcessResult:\n    _require_systemd_host()\n",
        (
            ") -> _ProcessResult:\n"
            '    if any("$" in argument for argument in command):\n'
            "        raise GitHubGatewayError(\n"
            '            "gateway command contains systemd environment expansion syntax"\n'
            "        )\n"
            "    _require_systemd_host()\n"
        ),
    ),
    ('            "--expand-environment=no",\n', ""),
    (
        'allowed_addresses=("127.0.0.53",),',
        'allowed_addresses=("127.0.0.11",),',
    ),
    (
        'if addresses == ("127.0.0.53",):',
        'if addresses == ("127.0.0.11",):',
    ),
)


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("usage: adapt-github-gateway.py PATH")
    path = Path(sys.argv[1])
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != _PREIMAGE:
        raise SystemExit("P3.8b GitHub gateway preimage changed")
    text = raw.decode("utf-8")
    for old, new in _REPLACEMENTS:
        if text.count(old) != 1:
            raise SystemExit("P3.8b GitHub gateway adaptation anchor changed")
        text = text.replace(old, new)
    modified = text.encode("utf-8")
    if hashlib.sha256(modified).hexdigest() != _POSTIMAGE:
        raise SystemExit("P3.8b GitHub gateway postimage changed")

    module = ast.parse(text)
    entrypoint = next(
        ast.literal_eval(node.value)
        for node in module.body
        if isinstance(node, ast.Assign)
        and any(
            isinstance(target, ast.Name) and target.id == "_ISOLATED_ENTRYPOINT"
            for target in node.targets
        )
    )
    compile(entrypoint, "<P3.8b isolated gateway>", "exec")
    path.write_bytes(modified)


if __name__ == "__main__":
    main()
