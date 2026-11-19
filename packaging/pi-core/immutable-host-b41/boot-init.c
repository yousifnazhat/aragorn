/* Initramfs PID 1, Linux/AArch64 only. No shell, insmod helper, or fallback init. */
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/fs.h>
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
#include <time.h>
#include <unistd.h>
#if !defined(__aarch64__) || __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error unsupported boot ABI
#endif

#define ROOT "/newroot"
#define DISK "/dev/nvme0n1"
#define PART DISK "p2"
#define MANAGER "/usr/lib/systemd/systemd"
#define CMDLINE "rdinit=/init init=/aragorn-no-fallback root=/dev/aragorn-no-kernel-fallback ro panic=0\n"
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
static int readonly_block(const char *path) {
        int ro = 0; struct stat s;
        int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
        need(fd >= 0 && fstat(fd, &s) == 0 && S_ISBLK(s.st_mode) &&
             ioctl(fd, BLKROGET, &ro) == 0 && ro == 1, "missing or writable NVMe device");
        return fd;
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
        int disk = readonly_block(DISK), part = readonly_block(PART);
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
        close(part); close(disk);
        need(mount("/proc", ROOT "/proc", NULL, MS_MOVE, NULL) == 0 &&
             mount("/dev", ROOT "/dev", NULL, MS_MOVE, NULL) == 0, "API filesystem handoff");
        need(chdir(ROOT) == 0 && mount(".", "/", NULL, MS_MOVE, NULL) == 0 &&
             chroot(".") == 0 && chdir("/") == 0, "root handoff");
        execveat(manager, "", argv, env, AT_EMPTY_PATH);
        need(0, "manager exec"); return 125;
}
