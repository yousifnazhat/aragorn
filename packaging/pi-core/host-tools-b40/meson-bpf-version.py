"""One request to the build parent, not a cached or fabricated bpftool version."""
import base64
import json
import os
from pathlib import Path
import re
import select
import stat
import sys


def main():
    if sys.argv[1:] != ["--version"]:
        raise ValueError("only the real host capability probe is permitted for these clients")
    tmp = Path(os.environ["TMPDIR"])
    root = tmp.parent / "bpf-query"
    owned = Path(__file__).resolve().parents[3] / ".aragorn/host-preflight/build-b40/client-work"
    if (tmp.name != "tmp" or tmp.parent.parent != owned or not re.fullmatch("[0-9a-f]{64}", tmp.parent.name)
            or root.resolve(strict=True) != root or root.lstat().st_uid != os.getuid()
            or stat.S_IMODE(root.lstat().st_mode) != 0o700):
        raise ValueError("unowned or missing capability request")
    def fifo(name, flags):
        p = root / name
        fd = os.open(p, flags | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        row = os.fstat(fd)
        if not (stat.S_ISFIFO(row.st_mode) and row.st_uid == os.getuid()
                and row.st_mode & 0o077 == 0 and row.st_nlink == 1 and os.path.samestat(row, p.lstat())):
            os.close(fd)
            raise ValueError("not a private owned FIFO")
        return fd
    read = fifo("response", os.O_RDONLY)
    try:
        send = fifo("request", os.O_WRONLY)
        try:
            if os.write(send, b"--version\n") != 10:
                raise ValueError("incomplete capability request")
        finally:
            os.close(send)
        if not select.select([read], [], [], 55)[0]:
            raise TimeoutError("no capability response")
        # The parent writes a single <= PIPE_BUF message; no streaming or retry.
        msg = os.read(read, 513)
        if not msg.endswith(b"\n") or len(msg) > 512:
            raise ValueError("missing or oversized capability response")
        result = json.loads(msg)
        if set(result) != {"rc", "stdout"} or type(result["rc"]) is not int or not 0 <= result["rc"] <= 255:
            raise ValueError("invalid capability response")
        sys.stdout.buffer.write(base64.b64decode(result["stdout"], validate=True))
        return result["rc"]
    finally:
        os.close(read)


if __name__ == "__main__":
    sys.exit(main())
