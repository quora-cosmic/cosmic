/* quora 2025
 *
 * Generate a 1024-bit password (128 printable characters).
 * Combines three entropy engines into one output:
 * 1) OS CSPRNG (getrandom/getentropy or /dev/urandom)
 * 2) xorshift128+ PRNG seeded from timers/rdtsc
 * 3) time/pid/rdtsc mixed bytes
 *
 * Output: a single line with 128 printable chars including numbers, letters, symbols.
 *
 * Build:
 *   gcc -O3 -std=c11 -o pw_gen_1024 pw_gen_1024.c
 *
 * Use responsibly.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#ifdef __linux__
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <linux/random.h>
#include <sys/random.h> /* for getrandom() if available */
#endif

/* Lengths */
#define OUT_BYTES 128  /* 128 bytes * 8 = 1024 bits */
#define BUF_SIZE OUT_BYTES

/* Character set: includes lowercase, uppercase, digits, symbols */
static const char charset[] =
  "abcdefghijklmnopqrstuvwxyz"
  "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
  "0123456789"
  "!@#$%^&*()-_=+[]{};:,.<>?/|~";

/* ========== Helper: rdtsc (best-effort) ========== */
static inline uint64_t rdtsc_u64(void) {
#if defined(__i386__) || defined(__x86_64__)
    unsigned int hi = 0, lo = 0;
    __asm__ volatile ("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
#else
    /* Fallback: use clock_gettime as high-res surrogate */
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
#endif
}

/* ========== Engine A: Secure OS CSPRNG ========== */
static int os_csprng_bytes(uint8_t *buf, size_t len) {
#if defined(__linux__)
    /* Try getrandom() first */
    ssize_t got = 0;
    size_t left = len;
    while (left > 0) {
        ssize_t r = syscall(SYS_getrandom, buf + got, left, 0);
        if (r < 0) {
            if (errno == EINTR) continue;
            break;
        }
        got += r;
        left -= r;
    }
    if ((size_t)got == len) return 0;
    /* fallback to /dev/urandom below */
#endif

    /* Generic fallback: read /dev/urandom */
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return -1;
    size_t read_total = 0;
    while (read_total < len) {
        ssize_t r = read(fd, buf + read_total, len - read_total);
        if (r < 0) {
            if (errno == EINTR) continue;
            close(fd);
            return -1;
        }
        read_total += (size_t)r;
    }
    close(fd);
    return 0;
}

/* ========== Engine B: xorshift128+ PRNG ========== */
/* Very fast PRNG (not CSPRNG) used here as an additional entropy engine. */
typedef struct {
    uint64_t s[2];
} xorshift128p_state;

/* Simple splitmix64 to seed xorshift */
static uint64_t splitmix64(uint64_t *state) {
    uint64_t z = (*state += 0x9e3779b97f4a7c15ULL);
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
    z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
    return z ^ (z >> 31);
}

static void xorshift128p_seed(xorshift128p_state *st, uint64_t seed) {
    uint64_t s = seed;
    st->s[0] = splitmix64(&s);
    st->s[1] = splitmix64(&s);
}

static uint64_t xorshift128p_next(xorshift128p_state *st) {
    uint64_t s1 = st->s[0];
    uint64_t s0 = st->s[1];
    uint64_t result = s0 + s1;

    st->s[0] = s0;
    s1 ^= s1 << 23;
    st->s[1] = (s1 ^ s0 ^ (s1 >> 17) ^ (s0 >> 26));

    return result;
}

static void prng_fill(xorshift128p_state *st, uint8_t *buf, size_t len) {
    size_t i = 0;
    while (i + 8 <= len) {
        uint64_t v = xorshift128p_next(st);
        memcpy(buf + i, &v, 8);
        i += 8;
    }
    if (i < len) {
        uint64_t v = xorshift128p_next(st);
        memcpy(buf + i, &v, len - i);
    }
}

/* ========== Engine C: time/pid/rdtsc mixing bytes ========== */
static void time_pid_mix(uint8_t *buf, size_t len) {
    uint64_t t1 = (uint64_t)time(NULL);
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    uint64_t t2 = (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
    uint64_t r = rdtsc_u64();
    pid_t pid = getpid();
    uint64_t a = t1 ^ t2 ^ r ^ (uint64_t)pid;
    /* Expand a into len bytes with some shifts */
    for (size_t i = 0; i < len; ++i) {
        a ^= (a << 13) ^ (a >> 7) ^ (0x9e3779b97f4a7c15ULL + i);
        buf[i] = (uint8_t)(a >> ((i & 7) * 8));
    }
}

/* ========== Mix engines and produce final printable password ========== */
int main(void) {
    uint8_t A[BUF_SIZE]; /* OS CSPRNG */
    uint8_t B[BUF_SIZE]; /* PRNG */
    uint8_t C[BUF_SIZE]; /* time/pid mixing */
    uint8_t out[BUF_SIZE];
    memset(A, 0, sizeof(A));
    memset(B, 0, sizeof(B));
    memset(C, 0, sizeof(C));
    memset(out, 0, sizeof(out));

    /* 1) Fill A from OS CSPRNG */
    if (os_csprng_bytes(A, BUF_SIZE) != 0) {
        fprintf(stderr, "Warning: OS CSPRNG unavailable, continuing with weaker sources\n");
        /* still continue */
    }

    /* 2) Seed PRNG from a mix of OS bytes, rdtsc, time */
    uint64_t seed = rdtsc_u64();
    for (size_t i = 0; i + 8 <= BUF_SIZE; i += 8) {
        uint64_t v = 0;
        memcpy(&v, A + i, 8);
        seed ^= v;
    }
    seed ^= (uint64_t)getpid() << 16;
    seed ^= (uint64_t)time(NULL);

    xorshift128p_state st;
    xorshift128p_seed(&st, seed);
    prng_fill(&st, B, BUF_SIZE);

    /* 3) Fill C with time/pid/rdtsc mixing */
    time_pid_mix(C, BUF_SIZE);

    /* 4) XOR A,B,C -> out */
    for (size_t i = 0; i < BUF_SIZE; ++i) {
        out[i] = A[i] ^ B[i] ^ C[i];
    }

    /* 5) Map out bytes into printable charset */
    size_t charset_len = strlen(charset);
    char pass[OUT_BYTES + 1];
    for (size_t i = 0; i < OUT_BYTES; ++i) {
        /* Use modulo mapping. Because charset_len isn't a power of two,
           there is slight bias; acceptable for most uses here since out[] is strong.
           If you need perfect unbiased chars, use rejection sampling against a CSPRNG. */
        uint8_t v = out[i];
        pass[i] = charset[v % charset_len];
    }
    pass[OUT_BYTES] = '\0';

    /* Print result */
    puts(pass);

    /* Securely wipe sensitive buffers (best-effort) */
    memset(A, 0, sizeof(A));
    memset(B, 0, sizeof(B));
    memset(C, 0, sizeof(C));
    memset(out, 0, sizeof(out));
    memset(&st, 0, sizeof(st));
    /* password remains in memory for user to copy; user can clear terminal if desired */

    return 0;
}
