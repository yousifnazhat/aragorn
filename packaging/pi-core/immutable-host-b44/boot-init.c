/* Initramfs PID 1, Linux/AArch64 only. No shell, insmod helper, or fallback init. */
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/fs.h>
#include <linux/magic.h>
#include <nettle/sha2.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/statvfs.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <time.h>
#include <unistd.h>
#if !defined(__aarch64__) || __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error unsupported boot ABI
#endif

#define ROOT "/newroot"
#define DISK "/dev/nvme0n1"
#define PART DISK "p2"
#define MANAGER "/usr/lib/systemd/systemd"
#define CMDLINE "rdinit=/init init=/aragorn-no-fallback root=/dev/aragorn-no-kernel-fallback ro panic=0 console=hvc0\n"
struct policy { char magic[8]; uint64_t bytes; unsigned char root[32], manager[32], loader[32]; };
_Static_assert(sizeof(struct policy) == 112, "invalid policy ABI");

static void need(int ok, const char *what) {
        if (!ok) {
                dprintf(STDERR_FILENO, "aragorn early boot refused: %s\n", what);
                _exit(125); /* Global PID 1 exit is fatal; never seek another init. */
        }
}
static void exact(int fd, void *buf, size_t n) {
        unsigned char *p = buf;
        while (n) { ssize_t got = read(fd, p, n); need(got > 0, "incomplete input"); p += got; n -= got; }
}
static void eof(int fd) { char b; need(read(fd, &b, 1) == 0, "surplus bytes"); }
static void hash(int fd, uint64_t n, const unsigned char *expected) {
        static unsigned char buf[256 * 1024];
        unsigned char got[32];
        struct sha256_ctx ctx;
        sha256_init(&ctx);
        while (n) {
                const size_t k = n < sizeof buf ? (size_t)n : sizeof buf;
                exact(fd, buf, k); sha256_update(&ctx, k, buf); n -= k;
        }
        sha256_digest(&ctx, sizeof got, got);
        need(memcmp(got, expected, sizeof got) == 0, "SHA-256 mismatch");
}
static int checked_file(const char *name, const unsigned char *digest) {
        struct stat s;
        int fd = open(name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
        need(fd >= 0 && fstat(fd, &s) == 0 && S_ISREG(s.st_mode) && s.st_uid == 0 &&
             s.st_gid == 0 && (s.st_mode & 0022) == 0 && (s.st_mode & 0111) &&
             s.st_size > 0 && s.st_size < 128 * 1024 * 1024, "invalid pinned executable");
        hash(fd, s.st_size, digest); eof(fd);
        return fd;
}
static struct stat directory(const char *name) {
        struct stat s;
        need(lstat(name, &s) == 0 && S_ISDIR(s.st_mode) && s.st_uid == 0 && s.st_gid == 0 &&
             !(s.st_mode & 0022), "linked, missing, or writable path component");
        return s;
}
static void readonly_fs(const char *name) {
        struct statvfs fs;
        need(statvfs(name, &fs) == 0 && (fs.f_flag & ST_RDONLY), "writable mount");
}
static int readonly_block(const char *path, int *ro) {
        struct stat s;
        int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
        need(fd >= 0 && fstat(fd, &s) == 0 && S_ISBLK(s.st_mode) &&
             ioctl(fd, BLKROGET, ro) == 0 && *ro == 1, "missing or writable NVMe device");
        return fd;
}

/* Direct guest output only. Linux hvc_console assigns hvc0 device 229:0. */
static int serial_output(void) {
        struct stat s;
        int fd = open("/dev/hvc0", O_WRONLY | O_NOCTTY | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW);
        need(fd >= 0 && fstat(fd, &s) == 0 && S_ISCHR(s.st_mode) && s.st_rdev == makedev(229, 0),
             "hvc0 not available");
        return fd;
}
static void boot_id(char out[37]) {
        char raw[37];
        int fd = open("/proc/sys/kernel/random/boot_id", O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
        need(fd >= 0, "kernel boot id"); exact(fd, raw, sizeof raw); eof(fd); close(fd);
        for (size_t i = 0; i < 36; ++i) {
                int sep = i == 8 || i == 13 || i == 18 || i == 23;
                need(sep ? raw[i] == '-' : ((raw[i] >= '0' && raw[i] <= '9') ||
                     (raw[i] >= 'a' && raw[i] <= 'f')), "kernel boot id format");
        }
        need(raw[36] == '\n' && raw[14] == '4' && strchr("89ab", raw[19]) != NULL, "kernel boot uuid");
        memcpy(out, raw, 36); out[36] = '\0';
}
static void hex_sha(char out[65], const unsigned char in[32]) {
        static const char hex[] = "0123456789abcdef";
        for (int i = 0; i < 32; ++i) {
                out[2*i] = hex[in[i] >> 4]; out[2*i+1] = hex[in[i] & 15];
        }
        out[64] = '\0';
}

struct mount_id { struct stat node; uint64_t mount; int ro; };
static struct mount_id mounted(int basedir, const char *path, int flags) {
        struct mount_id id; struct statx x; struct statfs fs; struct statvfs vfs;
        int fd = openat(basedir, path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | flags);
        need(fd >= 0 && fstat(fd, &id.node) == 0 && fstatfs(fd, &fs) == 0 &&
             fs.f_type == SQUASHFS_MAGIC && fstatvfs(fd, &vfs) == 0 &&
             statx(fd, "", AT_EMPTY_PATH, STATX_MNT_ID_UNIQUE, &x) == 0 &&
             (x.stx_mask & STATX_MNT_ID_UNIQUE) && x.stx_mnt_id != 0, "root mount identity");
        id.mount = x.stx_mnt_id; id.ro = !!(vfs.f_flag & ST_RDONLY);
        need(id.ro, "writable observed mount");
        close(fd); return id;
}
static int same_node(struct stat a, struct stat b) {
        return a.st_dev == b.st_dev && a.st_ino == b.st_ino;
}
/* This observes a kernel exec-file identity; it is not a systemd health check. */
static void report_after_exec(int serial, int manager, struct mount_id root, struct mount_id lib,
                              const struct policy *p, const char *uuid, int dro, int pro,
                              int sector, unsigned long long total) {
        struct stat expected, exe; struct statfs procfs;
        int proc = open("/proc/1", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        need(getpid() != 1 && getppid() == 1 && proc >= 0 && fstatfs(proc, &procfs) == 0 &&
             procfs.f_type == PROC_SUPER_MAGIC && fstat(manager, &expected) == 0, "observer inputs");
        struct timespec tick = {.tv_nsec = 10000000};
        int matched = 0;
        for (int i = 0; i < 500; ++i) {
                if (fstatat(proc, "exe", &exe, 0) == 0 && same_node(expected, exe)) { matched = 1; break; }
                nanosleep(&tick, NULL);
        }
        need(matched, "PID 1 pinned exec not observed");
        /* proc/1/root uses the target process's filesystem view, not the observer's root. */
        struct mount_id r = mounted(proc, "root", 0);
        struct mount_id l = mounted(proc, "root/lib", O_NOFOLLOW);
        struct mount_id u = mounted(proc, "root/usr/lib", O_NOFOLLOW);
        int bound = same_node(l.node, u.node);
        need(r.mount == root.mount && same_node(r.node, root.node) && l.mount == lib.mount &&
             same_node(l.node, lib.node) && u.mount == r.mount && r.mount != l.mount && bound,
             "PID 1 mount view");
        char manager_sha[65], root_sha[65], line[512];
        hex_sha(manager_sha, p->manager); hex_sha(root_sha, p->root);
        pid_t pid = getppid();
        need(pid == 1 && fstatat(proc, "exe", &exe, 0) == 0 && same_node(expected, exe),
             "PID 1 executable changed");
        int len = snprintf(line, sizeof line,
                "ARAGORN_B44_V1 boot=%s disk_ro=%d part_ro=%d sector=%d part_bytes=%llu "
                "root_ro=%d lib_ro=%d lib_same=%d pid=%d manager_sha256=%s root_sha256=%s\n",
                uuid, dro, pro, sector, total, r.ro, l.ro, bound, (int)pid, manager_sha, root_sha);
        need(len > 0 && (size_t)len < sizeof line && write(serial, line, (size_t)len) == len,
             "short serial observation");
        _exit(0);
}

int main(void) {
        static const char *const mods[] = {"hkdf", "nvme-auth", "nvme-keyring", "nvme-core", "nvme"};
        struct policy p; unsigned long long total = 0; int sector = 0;
        char cmd[sizeof CMDLINE - 1], path[96], *const argv[] = {MANAGER, NULL};
        char *const env[] = {"HOME=/", "PATH=/usr/sbin:/usr/bin:/sbin:/bin", NULL};
        need(getpid() == 1 && getuid() == 0, "not root PID 1");
        need(mount("devtmpfs", "/dev", "devtmpfs", MS_NOSUID, "mode=0755") == 0, "devtmpfs");
        need(mount("proc", "/proc", "proc", MS_NOSUID | MS_NOEXEC | MS_NODEV, NULL) == 0, "proc");
        int fd = open("/proc/cmdline", O_RDONLY | O_CLOEXEC);
        need(fd >= 0, "command line"); exact(fd, cmd, sizeof cmd); eof(fd); close(fd);
        need(memcmp(cmd, CMDLINE, sizeof cmd) == 0, "different kernel arguments");
        fd = open("/policy", O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
        need(fd >= 0, "no image policy"); exact(fd, &p, sizeof p); eof(fd); close(fd);
        need(memcmp(p.magic, "ARGBOOT1", 8) == 0 && p.bytes >= 4096 && p.bytes <= (8ULL << 30), "root policy");
        for (unsigned int i = 0; i < sizeof mods / sizeof mods[0]; ++i) {
                snprintf(path, sizeof path, "/modules/%s.ko", mods[i]);
                fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
                need(fd >= 0 && syscall(SYS_finit_module, fd, "", 0) == 0, mods[i]); close(fd);
        }
        /* Poll only for enumeration. Never repeat a module, mount, or exec operation. */
        struct timespec tick = {.tv_nsec = 100000000};
        for (int i = 0; access(PART, F_OK) != 0 && i < 300; ++i) nanosleep(&tick, NULL);
        int dro = 0, pro = 0;
        int disk = readonly_block(DISK, &dro), part = readonly_block(PART, &pro);
        need(ioctl(disk, BLKSSZGET, &sector) == 0 && sector == 512 &&
             ioctl(part, BLKGETSIZE64, &total) == 0 && total == ((p.bytes + 511) & ~511ULL), "root geometry");
        hash(part, p.bytes, p.root);
        for (uint64_t i = p.bytes; i < total; ++i) { unsigned char b; exact(part, &b, 1); need(b == 0, "root tail"); }
        eof(part);
        snprintf(path, sizeof path, "/proc/self/fd/%d", part);
        need(mount(path, ROOT, "squashfs", MS_RDONLY, NULL) == 0, "pinned root mount");
        readonly_fs(ROOT); directory(ROOT "/usr"); directory(ROOT "/usr/lib");
        directory(ROOT "/lib"); directory(ROOT "/dev"); directory(ROOT "/proc"); directory(ROOT "/usr/lib/systemd");
        DIR *lib = opendir(ROOT "/lib"); need(lib != NULL, "lib mountpoint");
        struct dirent *d; errno = 0;
        while ((d = readdir(lib))) need(strcmp(d->d_name, ".") == 0 || strcmp(d->d_name, "..") == 0, "nonempty /lib");
        need(errno == 0, "incomplete directory read"); closedir(lib);
        need(mount(ROOT "/usr/lib", ROOT "/lib", NULL, MS_BIND, NULL) == 0 &&
             mount(NULL, ROOT "/lib", NULL, MS_BIND | MS_REMOUNT | MS_RDONLY, NULL) == 0, "/lib bind");
        readonly_fs(ROOT "/lib");
        struct stat a = directory(ROOT "/usr/lib"), b = directory(ROOT "/lib");
        need(a.st_dev == b.st_dev && a.st_ino == b.st_ino, "different bound directory");
        close(checked_file(ROOT "/lib/ld-linux-aarch64.so.1", p.loader));
        int manager = checked_file(ROOT MANAGER, p.manager);
        struct mount_id root = mounted(AT_FDCWD, ROOT, O_NOFOLLOW);
        struct mount_id libmount = mounted(AT_FDCWD, ROOT "/lib", O_NOFOLLOW);
        struct stat partition, init_exe, target;
        need(fstat(part, &partition) == 0 && root.node.st_dev == partition.st_rdev &&
             libmount.node.st_dev == root.node.st_dev && libmount.mount != root.mount, "partition root/bind join");
        need(stat("/proc/1/exe", &init_exe) == 0 && fstat(manager, &target) == 0 &&
             !same_node(init_exe, target), "init not distinct from manager");
        char uuid[37]; boot_id(uuid);
        int serial = serial_output();
        close(part); close(disk);
        need(mount("/proc", ROOT "/proc", NULL, MS_MOVE, NULL) == 0 &&
             mount("/dev", ROOT "/dev", NULL, MS_MOVE, NULL) == 0, "API filesystem handoff");
        need(chdir(ROOT) == 0 && mount(".", "/", NULL, MS_MOVE, NULL) == 0 &&
             chroot(".") == 0 && chdir("/") == 0, "root handoff");
        pid_t witness = fork();
        need(witness >= 0, "create exec observer");
        if (witness == 0) report_after_exec(serial, manager, root, libmount, &p, uuid, dro, pro, sector, total);
        close(serial);
        execveat(manager, "", argv, env, AT_EMPTY_PATH);
        need(0, "manager exec"); return 125;
}
