"""Fixed, unprivileged calculate-and-save capability for the local walkthrough."""

import errno
import json
import os
import re
import sys


def main():
    if (os.geteuid(), os.getegid(), os.getgroups()) != (65534, 65534, []):
        raise SystemExit("unexpected worker identity")
    with open("/proc/self/status", encoding="ascii") as status:
        masks = [line.split(":", 1)[1].strip() for line in status if line.startswith("CapEff:")]
    if len(masks) != 1 or int(masks[0], 16) != 0:
        raise SystemExit("unexpected worker capabilities")

    operands = sys.argv[1:] or ["1", "2"]
    if len(operands) != 2 or not all(re.fullmatch(r"0|-?[1-9][0-9]{0,9}", s) for s in operands):
        raise SystemExit("expected two canonical decimal integers")
    numbers = tuple(int(s, 10) for s in operands)
    if not all(-2**31 <= n < 2**31 for n in numbers):
        raise SystemExit("operand outside signed 32-bit range")
    value = {"total": sum(numbers)}
    for target, decision in (("result.json", "ALLOW"), ("forbidden.json", "BLOCK")):
        print(json.dumps({"op": "create", "target": target, "value": value}), flush=True)
        if sys.stdin.readline() != decision + "\n":
            raise SystemExit("unexpected response for " + target)

    try:
        fd = os.open("/fixture/out/forbidden.json", os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except OSError as error:
        if error.errno != errno.EACCES:
            raise
        print("DIRECT EACCES", flush=True)
    else:
        os.close(fd)
        raise SystemExit("direct write unexpectedly succeeded")


if __name__ == "__main__":
    main()
