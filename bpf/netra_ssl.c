// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
//
// TLS plaintext sampler — uprobes on OpenSSL's SSL_write / SSL_read (and the
// _ex variants), so application protocol metadata is visible for TLS traffic
// that the packet-level sampler (netra_l7sample.c) cannot read.
//
// THIS OBSERVES PLAINTEXT before encryption and after decryption. It is strictly
// opt-in (NETRA_TLS_UPROBES, off by default) and the agent exports only bounded
// metadata (docs/tls-plaintext.md). The bytes are copied into a ring buffer for
// the agent to classify and discard; nothing is stored. An operator can restrict
// it to named processes with an allowlist (ssl_comm_allow), enforced here in the
// kernel before any byte is copied.
//
// Observe-only and fail-open: a failed read or a full ring buffer drops the
// sample, never affects the traced process. Samples are rate-limited per
// (process, SSL connection, direction).
//
// One object for every architecture. The registers holding the arguments live at
// different offsets of struct pt_regs on x86_64 and arm64, so the agent writes
// those offsets into L before load and this program reads registers through
// bpf_probe_read_kernel at them, rather than compiling per architecture.

#include <linux/bpf.h>

#define SEC(NAME) __attribute__((section(NAME), used))
#define __uint(name, val) int (*name)[val]
#define __type(name, val) val *name

static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)BPF_FUNC_map_lookup_elem;
static long (*bpf_map_update_elem)(void *map, const void *key, const void *value, __u64 flags) = (void *)BPF_FUNC_map_update_elem;
static long (*bpf_map_delete_elem)(void *map, const void *key) = (void *)BPF_FUNC_map_delete_elem;
static long (*bpf_probe_read_user)(void *dst, __u32 size, const void *unsafe_ptr) = (void *)BPF_FUNC_probe_read_user;
static long (*bpf_probe_read_kernel)(void *dst, __u32 size, const void *unsafe_ptr) = (void *)BPF_FUNC_probe_read_kernel;
static __u64 (*bpf_ktime_get_ns)(void) = (void *)BPF_FUNC_ktime_get_ns;
static __u64 (*bpf_get_current_pid_tgid)(void) = (void *)BPF_FUNC_get_current_pid_tgid;
static __u64 (*bpf_get_current_cgroup_id)(void) = (void *)BPF_FUNC_get_current_cgroup_id;
static long (*bpf_get_current_comm)(void *buf, __u32 size) = (void *)BPF_FUNC_get_current_comm;
static void *(*bpf_ringbuf_reserve)(void *ringbuf, __u64 size, __u64 flags) = (void *)BPF_FUNC_ringbuf_reserve;
static void (*bpf_ringbuf_submit)(void *data, __u64 flags) = (void *)BPF_FUNC_ringbuf_submit;
static void (*bpf_ringbuf_discard)(void *data, __u64 flags) = (void *)BPF_FUNC_ringbuf_discard;

#define SSL_COPY 128

#define DIR_WRITE 0 // plaintext handed to SSL_write: about to be encrypted and sent
#define DIR_READ  1 // plaintext SSL_read returned: just decrypted

// ssl_stats slots.
#define SSL_STAT_ELIGIBLE      0 // calls that carried data, from an observed process
#define SSL_STAT_EMITTED       1
#define SSL_STAT_RATE_LIMITED  2
#define SSL_STAT_RINGBUF_FULL  3
#define SSL_STAT_READ_FAIL     4 // a register or the buffer could not be read
#define SSL_STAT_COMM_FILTERED 5 // skipped by the process allowlist
#define SSL_STAT_SLOTS         8

// Bounds check the compiler cannot delete. After a helper call clobbers the
// registers clang recomputes a value from an unbounded source and drops a guard it
// can prove redundant from the C; the verifier only sees the recomputed register.
// The empty asm makes the value opaque so the comparison stays in the bytecode.
#define OPAQUE(v) asm volatile("" : "+r"(v))

// Offsets of the argument and return registers within struct pt_regs (bytes),
// written by the agent from runtime.GOARCH. valid == 0: do nothing.
struct ssl_layout {
    __u16 arg1;
    __u16 arg2;
    __u16 arg3;
    __u16 arg4;
    __u16 ret;
    __u8 valid;
    __u8 pad;
};

const volatile struct ssl_layout L;

struct ssl_event {
    __u64 ts_ns;
    __u64 pid_tgid;
    __u64 cgroup_id;
    __u64 ssl;      // the SSL* (identifies the connection within the process)
    __u8 dir;
    __u8 pad[3];
    __u16 len;      // bytes in data
    __u16 pad2;
    __u8 comm[16];
    __u8 data[SSL_COPY];
} __attribute__((packed));

struct comm_key {
    __u8 c[16];
};

struct read_args {
    __u64 ssl;
    __u64 buf;
    __u64 outp; // SSL_read_ex: where the byte count is stored
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} ssl_events SEC(".maps");

// Slot 0: minimum ns between samples of one connection+direction.
// Slot 1: nonzero means only processes in ssl_comm_allow are observed.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, __u64);
} ssl_cfg SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, struct comm_key);
    __type(value, __u8);
} ssl_comm_allow SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 32768);
    __type(key, __u64);
    __type(value, __u64);
} ssl_rate SEC(".maps");

// SSL_read is sampled on return (that is when the plaintext exists); its buffer
// and connection are remembered per thread from entry to return.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16384);
    __type(key, __u64);
    __type(value, struct read_args);
} ssl_read_args SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, SSL_STAT_SLOTS);
    __type(key, __u32);
    __type(value, __u64);
} ssl_stats SEC(".maps");

static __always_inline void stat_inc(__u32 slot)
{
    __u64 *v = bpf_map_lookup_elem(&ssl_stats, &slot);
    if (v)
        *v += 1;
}

// Reads one 8-byte register of the probed function's saved user registers.
static __always_inline int reg(void *ctx, __u16 off, __u64 *out)
{
    return bpf_probe_read_kernel(out, sizeof(*out), (const char *)ctx + off);
}

// Copies up to SSL_COPY bytes of plaintext at buf and sends a sample.
static __always_inline void emit(__u8 dir, __u64 ssl, __u64 buf, __u64 want)
{
    if (!buf || !want)
        return;

    __u32 zero = 0, one = 1;
    __u64 pid_tgid = bpf_get_current_pid_tgid();

    __u8 comm[16] = {};
    bpf_get_current_comm(comm, sizeof(comm));
    __u64 *use = bpf_map_lookup_elem(&ssl_cfg, &one);
    if (use && *use) {
        struct comm_key k = {};
        __builtin_memcpy(k.c, comm, sizeof(comm));
        if (!bpf_map_lookup_elem(&ssl_comm_allow, &k)) {
            stat_inc(SSL_STAT_COMM_FILTERED);
            return;
        }
    }
    // Eligible means "a candidate for sampling": it comes after the allowlist, so
    // eligible = emitted + rate_limited + ringbuf_full + read_fail and the ratio
    // eligible/emitted is the true sampling factor, not inflated by calls from
    // processes the operator never asked to observe.
    stat_inc(SSL_STAT_ELIGIBLE);

    __u64 now = bpf_ktime_get_ns();
    __u64 *gap = bpf_map_lookup_elem(&ssl_cfg, &zero);
    if (gap && *gap) {
        __u64 key = ssl ^ (pid_tgid << 32) ^ ((__u64)dir << 63);
        __u64 *last = bpf_map_lookup_elem(&ssl_rate, &key);
        if (last && now - *last < *gap) {
            stat_inc(SSL_STAT_RATE_LIMITED);
            return;
        }
        bpf_map_update_elem(&ssl_rate, &key, &now, BPF_ANY);
    }

    struct ssl_event *e = bpf_ringbuf_reserve(&ssl_events, sizeof(*e), 0);
    if (!e) {
        stat_inc(SSL_STAT_RINGBUF_FULL);
        return;
    }
    __u32 n = want > SSL_COPY ? SSL_COPY : (__u32)want;
    OPAQUE(n);
    if (n > SSL_COPY) {
        bpf_ringbuf_discard(e, 0);
        return;
    }
    __builtin_memset(e->data, 0, SSL_COPY);
    if (bpf_probe_read_user(e->data, n, (const void *)buf)) {
        bpf_ringbuf_discard(e, 0);
        stat_inc(SSL_STAT_READ_FAIL);
        return;
    }
    e->ts_ns = now;
    e->pid_tgid = pid_tgid;
    e->cgroup_id = bpf_get_current_cgroup_id();
    e->ssl = ssl;
    e->dir = dir;
    e->pad[0] = e->pad[1] = e->pad[2] = 0;
    e->len = (__u16)n;
    e->pad2 = 0;
    __builtin_memcpy(e->comm, comm, sizeof(comm));
    bpf_ringbuf_submit(e, 0);
    stat_inc(SSL_STAT_EMITTED);
}

// int SSL_write(SSL *ssl, const void *buf, int num)
SEC("uprobe/SSL_write")
int netra_ssl_write(void *ctx)
{
    if (!L.valid)
        return 0;
    __u64 ssl = 0, buf = 0, num = 0;
    if (reg(ctx, L.arg1, &ssl) || reg(ctx, L.arg2, &buf) || reg(ctx, L.arg3, &num)) {
        stat_inc(SSL_STAT_READ_FAIL);
        return 0;
    }
    // num is a C int in the low 32 bits of the register; the upper half is not defined.
    __s32 n = (__s32)num;
    if (n <= 0)
        return 0;
    emit(DIR_WRITE, ssl, buf, (__u64)n);
    return 0;
}

// int SSL_write_ex(SSL *ssl, const void *buf, size_t num, size_t *written)
SEC("uprobe/SSL_write_ex")
int netra_ssl_write_ex(void *ctx)
{
    if (!L.valid)
        return 0;
    __u64 ssl = 0, buf = 0, num = 0;
    if (reg(ctx, L.arg1, &ssl) || reg(ctx, L.arg2, &buf) || reg(ctx, L.arg3, &num)) {
        stat_inc(SSL_STAT_READ_FAIL);
        return 0;
    }
    emit(DIR_WRITE, ssl, buf, num);
    return 0;
}

static __always_inline int read_enter(void *ctx, int with_outp)
{
    if (!L.valid)
        return 0;
    struct read_args a = {};
    if (reg(ctx, L.arg1, &a.ssl) || reg(ctx, L.arg2, &a.buf)) {
        stat_inc(SSL_STAT_READ_FAIL);
        return 0;
    }
    if (with_outp && reg(ctx, L.arg4, &a.outp)) {
        stat_inc(SSL_STAT_READ_FAIL);
        return 0;
    }
    __u64 key = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&ssl_read_args, &key, &a, BPF_ANY);
    return 0;
}

// int SSL_read(SSL *ssl, void *buf, int num)
SEC("uprobe/SSL_read")
int netra_ssl_read(void *ctx)
{
    return read_enter(ctx, 0);
}

// int SSL_read_ex(SSL *ssl, void *buf, size_t num, size_t *readbytes)
SEC("uprobe/SSL_read_ex")
int netra_ssl_read_ex(void *ctx)
{
    return read_enter(ctx, 1);
}

SEC("uretprobe/SSL_read")
int netra_ssl_read_ret(void *ctx)
{
    __u64 key = bpf_get_current_pid_tgid();
    struct read_args *a = bpf_map_lookup_elem(&ssl_read_args, &key);
    if (!a)
        return 0;
    struct read_args args = *a;
    bpf_map_delete_elem(&ssl_read_args, &key);
    if (!L.valid)
        return 0;
    __u64 ret = 0;
    if (reg(ctx, L.ret, &ret)) {
        stat_inc(SSL_STAT_READ_FAIL);
        return 0;
    }
    __s32 n = (__s32)ret; // int return: bytes read, or <= 0
    if (n <= 0)
        return 0;
    emit(DIR_READ, args.ssl, args.buf, (__u64)n);
    return 0;
}

SEC("uretprobe/SSL_read_ex")
int netra_ssl_read_ex_ret(void *ctx)
{
    __u64 key = bpf_get_current_pid_tgid();
    struct read_args *a = bpf_map_lookup_elem(&ssl_read_args, &key);
    if (!a)
        return 0;
    struct read_args args = *a;
    bpf_map_delete_elem(&ssl_read_args, &key);
    if (!L.valid)
        return 0;
    __u64 ret = 0;
    if (reg(ctx, L.ret, &ret)) {
        stat_inc(SSL_STAT_READ_FAIL);
        return 0;
    }
    if ((__s32)ret != 1 || !args.outp) // 1 is success
        return 0;
    __u64 n = 0;
    if (bpf_probe_read_user(&n, sizeof(n), (const void *)args.outp)) {
        stat_inc(SSL_STAT_READ_FAIL);
        return 0;
    }
    emit(DIR_READ, args.ssl, args.buf, n);
    return 0;
}

char _license[] SEC("license") = "Dual BSD/GPL";
