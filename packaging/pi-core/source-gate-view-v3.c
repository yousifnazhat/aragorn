/* Fixed pre-exec view, Linux arm64. No commands, output channel or forwarded inputs. */
#if !defined(__linux__) || !defined(__aarch64__)
#error "The protected source gate is Linux arm64 only"
#endif
_Static_assert(sizeof(long) == 8, "arm64 syscall word required");

static const char gate[] __attribute__((used)) = "/opt/aragorn/pi-runtime/observer/source-gate";
static const char node[] = "/opt/aragorn/pi-runtime/node/bin/node";
static const char restriction[] = "--disallow-code-generation-from-strings";
static const char entry[] = "/opt/aragorn/pi-runtime/pi-core/entrypoint.js";
static const char home[] = "HOME=/nonexistent";
static const char path[] = "PATH=/opt/aragorn/pi-runtime/node/bin";

/* Linux statx UAPI. The kernel writes 256 bytes; consume only masked identity fields. */
struct sx {
    unsigned int mask, blksize;
    unsigned long attributes;
    unsigned int nlink, uid, gid;
    unsigned short mode, pad;
    unsigned long ino;
    unsigned char to_devices[0x80 - 0x28];
    unsigned int rmajor, rminor, major, minor;
    unsigned long mount;
    unsigned char rest[256 - 0x98];
};
_Static_assert(sizeof(struct sx) == 256 && __builtin_offsetof(struct sx, mode) == 0x1c &&
               __builtin_offsetof(struct sx, ino) == 0x20 && __builtin_offsetof(struct sx, rmajor) == 0x80 &&
               __builtin_offsetof(struct sx, major) == 0x88 && __builtin_offsetof(struct sx, mount) == 0x90,
               "statx identity layout");
enum { CWD = -100, NOFOLLOW = 0x100, EMPTY_PATH = 0x1000, WANTED = 0x111f,
       LIST_FLAGS = 040000 | 0100000 | 02000000 }; /* ARM64 directory, nofollow, cloexec */

static long call5(long nr, long a, long b, long c, long d, long e)
{
    register long x0 __asm__("x0") = a, x1 __asm__("x1") = b, x2 __asm__("x2") = c;
    register long x3 __asm__("x3") = d, x4 __asm__("x4") = e, x8 __asm__("x8") = nr;
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x8) : "memory", "cc");
    return x0;
}

__attribute__((noreturn)) static void refuse(void)
{
    call5(93, 126, 0, 0, 0, 0);
    __builtin_trap();
}

static int equal(const char *a, const char *b)
{
    if (!a) return 0;
    while (*b && *a == *b) { ++a; ++b; }
    return *a == *b;
}

static void metadata(long fd, const char *name, long flags, struct sx *s)
{
    if (call5(291, fd, (long)name, flags, WANTED, (long)s) != 0 ||
        (s->mask & WANTED) != WANTED || !s->mount || !s->ino) refuse();
}

static void endpoint(const char *parent, const char *socket)
{
    struct sx d, s;
    metadata(CWD, parent, NOFOLLOW, &d);
    if (d.mode != 0040711 || d.uid || !d.gid) refuse();
    /* EACCES opening for enumeration, not an empty successful getdents result. */
    if (call5(56, CWD, (long)parent, LIST_FLAGS, 0, 0) != -13) refuse();
    metadata(CWD, socket, NOFOLLOW, &s);
    if (s.mode != 0140660 || s.uid || s.gid != d.gid || s.nlink != 1 ||
        s.mount != d.mount || s.major != d.major || s.minor != d.minor || s.ino == d.ino) refuse();
}

static void link_view(const char *name, const char *expected, struct sx *target)
{
    struct sx link;
    char text[64];
    metadata(CWD, name, NOFOLLOW, &link);
    if ((link.mode & 0170000) != 0120000) refuse();
    long n = call5(78, CWD, (long)name, (long)text, sizeof(text), 0);
    if (n <= 0 || n >= (long)sizeof(text)) refuse();
    for (long i = 0; i < n; ++i)
        if (!expected[i] || text[i] != expected[i]) refuse();
    if (expected[n]) refuse();
    metadata(CWD, name, 0, target);
}

static int same_object(const struct sx *a, const struct sx *b)
{
    return a->mount == b->mount && a->major == b->major && a->minor == b->minor && a->ino == b->ino &&
           a->mode == b->mode && a->rmajor == b->rmajor && a->rminor == b->rminor;
}

static void stdio_alias(const char *name, const char *text, long fd)
{
    struct sx followed, held;
    link_view(name, text, &followed);
    metadata(fd, "", NOFOLLOW | EMPTY_PATH, &held);
    if ((held.mode & 0170000) != 0020000 || held.rmajor != 1 || held.rminor != 3 ||
        !same_object(&followed, &held)) refuse();
}

static void fixed_view(long pid)
{
    /* Synthesize expected link TEXT only. No computed pathname is passed to the kernel. */
    char decimal[12], thread[32];
    unsigned int i = sizeof(decimal) - 1, j = 0;
    unsigned long n = (unsigned long)pid;
    decimal[i] = 0;
    do { decimal[--i] = (char)('0' + n % 10); n /= 10; } while (n);
    for (const char *p = decimal+i; *p; ++p) thread[j++] = *p;
    for (const char *p = "/task/"; *p; ++p) thread[j++] = *p;
    for (const char *p = decimal+i; *p; ++p) thread[j++] = *p;
    thread[j] = 0;

    endpoint("/run/aragorn-pi-bootstrap/requests", "/run/aragorn-pi-bootstrap/requests/request.sock");
    endpoint("/run/aragorn-pi-bootstrap/provider", "/run/aragorn-pi-bootstrap/provider/provider.sock");
    struct sx a, b;
    link_view("/proc/self", decimal+i, &a);
    link_view("/proc/thread-self", thread, &b);
    if ((a.mode & 0170000) != 0040000 || (b.mode & 0170000) != 0040000) refuse();
    link_view("/dev/fd", "/proc/self/fd", &a);
    metadata(CWD, "/proc/self/fd", 0, &b);
    if ((b.mode & 0170000) != 0040000 || !same_object(&a, &b)) refuse();
    stdio_alias("/dev/stdin",  "/proc/self/fd/0", 0);
    stdio_alias("/dev/stdout", "/proc/self/fd/1", 1);
    stdio_alias("/dev/stderr", "/proc/self/fd/2", 2);
}

__attribute__((used, noreturn)) void gate_main(const unsigned long *stack)
{
    const char *const *argv = (const char *const *)(stack + 1);
    const char *child_argv[] = {node, restriction, entry, 0};
    const char *child_env[] = {home, path, 0};
    if (stack[0] != 4 || !equal(argv[0], gate) || !equal(argv[1], node) ||
        !equal(argv[2], restriction) || !equal(argv[3], entry) || argv[4] != 0) refuse();
    if (call5(436, 3, 0xffffffffUL, 2, 0, 0) != 0) refuse(); /* close_range(UNSHARE) */
    long pid = call5(172, 0, 0, 0, 0, 0);
    if (pid <= 0 || pid > 0x7fffffff || call5(129, pid, 19, 0, 0, 0) != 0) refuse();
    fixed_view(pid);
    if (call5(129, pid, 19, 0, 0, 0) != 0) refuse(); /* final independent-observer latch */
    call5(221, (long)node, (long)child_argv, (long)child_env, 0, 0);
    refuse();
}

__asm__(".global _start\n"
        ".type _start, %function\n"
        "_start:\n"
        "mov x0, sp\n"
        "bl gate_main\n"
        "brk #0\n");
