"""Inert mountinfo records for the B54 role projection; no namespace or mount access."""
import unittest

from aragorn.pi_core_state_mounts import ACTION, ANCHOR, PROVIDER, verify_mounts


def sample_mountinfo(role, device="253:0", fs_type="ext4"):
    rows = ["1 99 7:0 / / ro - squashfs /dev/nvme0n1p2 ro"]
    if role == "pi":
        rows = ["1 99 8:1 / / ro - squashfs /dev/sda1 ro",
                "2 1 0:21 / /dev rw,nosuid - tmpfs tmpfs rw",
                "3 1 8:2 /bundle /var/lib/aragorn/admitted/.aragorn-versions/example ro - ext4 /dev/sda2 rw"]
    if role == "manager":
        rows.append("2 1 0:28 / /run rw,nosuid,nodev - tmpfs tmpfs rw")
    targets = {"manager": [(3, 2, "/", ANCHOR), (4, 1, ACTION, ACTION), (5, 1, PROVIDER, PROVIDER)],
               "action": [(4, 1, ACTION, ACTION)], "sensor": [(4, 1, ACTION, ACTION)],
               "provider": [], "pi": []}[role]
    for idx, parent, root, path in targets:
        flags = "ro" if role == "sensor" else "rw"
        rows.append(f"{idx} {parent} {device} {root} {path} {flags},nodev,nosuid,noexec - {fs_type} /dev/mapper/pilot rw")
    return ("\n".join(rows) + "\n").encode("ascii")


class OfflineMounts(unittest.TestCase):
    def check(self, role, raw):
        return verify_mounts(role, raw, device="253:0", fs_type="ext4")

    def test_five_role_projections_from_raw_mountinfo(self):
        for role, expected in (("manager", {ANCHOR: 3, ACTION: 4, PROVIDER: 5}), ("action", {ACTION: 4}),
                               ("sensor", {ACTION: 4}), ("provider", {}), ("pi", {})):
            with self.subTest(role=role):
                self.assertEqual(self.check(role, sample_mountinfo(role)), expected)

    def test_no_substitute_for_required_exact_mounts(self):
        raw = sample_mountinfo("manager")
        for bad in (sample_mountinfo("action"), raw.replace(b"253:0", b"253:1"), raw.replace(b"ext4", b"xfs"),
                    raw.replace(ANCHOR.encode(), b"/wrong"), raw.replace(ACTION.encode(), b"/different", 1),
                    raw.replace(b"- ext4", b"shared:42 - ext4", 1), raw.replace(b"nodev,", b"", 1),
                    raw.replace(b"noexec ", b"noexec,exec ", 1), raw.replace(b"/dev/mapper/pilot rw", b"/dev/other rw", 1)):
            with self.subTest(example=bad[-150:]), self.assertRaises(ValueError):
                self.check("manager", bad)

    def test_complete_namespace_is_exported_only_after_all_rows_validate(self):
        namespace = {}
        raw = sample_mountinfo("pi")
        args = {"device": "253:0", "fs_type": "ext4", "namespace": namespace}
        with self.assertRaises(ValueError):
            verify_mounts("pi", raw.replace(b"3 1 ", b"3 2 "), **args)
        self.assertEqual(namespace, {})
        self.assertEqual(verify_mounts("pi", raw, **args), {})
        self.assertEqual(namespace, {"/": (1, "8:1"), "/dev": (2, "0:21"),
                                    "/var/lib/aragorn/admitted/.aragorn-versions/example": (3, "8:2")})

    def test_service_roles_are_not_interchangeable_and_sensor_cannot_write(self):
        sensor = sample_mountinfo("sensor")
        for role, raw in (("sensor", sample_mountinfo("action")), ("action", sensor),
                          ("sensor", sensor.replace(b"ro,nodev", b"ro,rw,nodev")),
                          ("provider", sensor), ("pi", sensor), ("action", sample_mountinfo("manager"))):
            with self.subTest(role=role), self.assertRaises(ValueError):
                self.check(role, raw)

    def test_aliases_and_cross_filesystem_shadows_refuse(self):
        alias = b"25 1 253:0 / /tmp/ordinary ro,nodev,nosuid,noexec - ext4 /dev/mapper/pilot rw\n"
        child = f"24 4 0:11 / {ACTION}/protected rw - tmpfs tmpfs rw\n".encode()
        for role, extra in (("sensor", alias), ("pi", alias), ("action", child), ("sensor", child),
                            ("manager", child), ("pi", b"12 1 0:17 / /var/lib rw - tmpfs tmpfs rw\n"),
                            ("pi", b"12 1 0:17 / /tmp rw - overlay overlay rw,lowerdir=/outside\n"),
                            ("pi", f"12 1 8:8 {PROVIDER} /tmp ro - ext4 /dev/other rw\n".encode())):
            with self.subTest(role=role, extra=extra), self.assertRaises(ValueError):
                self.check(role, sample_mountinfo(role) + extra)

    def test_physical_encryption_backing_cannot_be_mounted_even_read_only(self):
        for role in ("manager", "action", "sensor", "pi", "provider"):
            for dev in ("259:0", "253:4"):
                hidden = f"17 1 {dev} / /innocent ro - ext4 /dev/disk/by-id/alias rw\n".encode()
                with self.subTest(role=role, dev=dev), self.assertRaisesRegex(ValueError, "physical backing"):
                    verify_mounts(role, sample_mountinfo(role) + hidden, device="253:0", fs_type="ext4",
                                  backing_devices=["253:4", "259:0"])

    def test_incomplete_duplicate_hidden_or_malformed_rows_refuse(self):
        raw = sample_mountinfo("manager")
        for bad in (b"", raw[:-1], raw.partition(b"\n")[2], raw + raw.split(b"\n", 1)[0] + b"\n",
                    raw.replace(b"5 1 ", b"9 77 "), raw.replace(b"3 2 ", b"3 1 "),
                    raw.replace(b"1 99 ", b"1 3 "), raw.replace(b"/run ", b"/r\\123un "),
                    raw.replace(b"0:28", b"0:028"), raw.replace(b" - squashfs ", b" xyz - squashfs ", 1),
                    raw + b"6 1 0:5 / /tmp rw - tmpfs tmpfs rw\x00\n"):
            with self.subTest(example=bad[:55]), self.assertRaises(ValueError):
                self.check("manager", bad)
