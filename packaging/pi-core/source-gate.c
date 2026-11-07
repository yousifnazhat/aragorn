/* Fixed Linux arm64 pre-Node gate. No libc, loader, allocator or file reads. */
#if !defined(__linux__) || !defined(__aarch64__)
#error "The protected source gate is Linux arm64 only"
#endif

_Static_assert(sizeof(long) == 8, "arm64 syscall word required");

static const char node[] = "/opt/aragorn/pi-runtime/node/bin/node";
static const char entry[] = "/opt/aragorn/pi-runtime/pi-core/entrypoint.js";
static const char home[] = "HOME=/nonexistent";
static const char path[] = "PATH=/opt/aragorn/pi-runtime/node/bin";

static long call3(long number, long a, long b, long c)
{
    register long x0 __asm__("x0") = a;
    register long x1 __asm__("x1") = b;
    register long x2 __asm__("x2") = c;
    register long x8 __asm__("x8") = number;
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x1), "r"(x2), "r"(x8) : "memory", "cc");
    return x0;
}

static int equal(const char *actual, const char *expected)
{
    unsigned long i = 0;
    while (expected[i]) {
        if (actual[i] != expected[i]) return 0;
        ++i;
    }
    return actual[i] == 0;
}

__attribute__((noreturn)) static void refuse(void)
{
    call3(93, 126, 0, 0); /* exit; no fallback or automatic retry */
    __builtin_trap();
}

__attribute__((used, noreturn)) void gate_main(const unsigned long *stack)
{
    const char *const *argv = (const char *const *)(stack + 1);
    const char *child_argv[] = {node, entry, 0};
    const char *child_env[] = {home, path, 0};
    long pid;

    if (stack[0] != 3 || !equal(argv[1], node) || !equal(argv[2], entry)) refuse();
    /* Unshare and close inherited nonstdio descriptors before the owned stop. */
    if (call3(436, 3, 0xffffffffUL, 2) != 0) refuse();
    pid = call3(172, 0, 0, 0);
    if (pid <= 0 || call3(129, pid, 19, 0) != 0) refuse();
    /* The supervisor must seize this exact stopped generation before release. */
    call3(221, (long)node, (long)child_argv, (long)child_env);
    refuse();
}

__asm__(".global _start\n"
        ".type _start, %function\n"
        "_start:\n"
        "mov x0, sp\n"
        "bl gate_main\n"
        "brk #0\n");
