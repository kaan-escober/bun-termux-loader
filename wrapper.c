#include <elf.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#define LD_SO     "/data/data/com.termux/files/usr/glibc/lib/ld-linux-aarch64.so.1"
#define GLIBC_LIB "/data/data/com.termux/files/usr/glibc/lib"
#define MAX_ARGS  256
#define MAX_ENV   512
#define MAX_LIBS  32

static void die(const char *msg) {
    write(STDERR_FILENO, "error: ", 7);
    write(STDERR_FILENO, msg, strlen(msg));
    write(STDERR_FILENO, "\n", 1);
    _exit(1);
}

static void read_all(int fd, void *buf, size_t n) {
    uint8_t *p = buf;
    while (n > 0) {
        ssize_t r = read(fd, p, n);
        if (r <= 0) die("read failed");
        p += r;
        n -= r;
    }
}

static void write_all(int fd, const void *buf, size_t n) {
    const uint8_t *p = buf;
    while (n > 0) {
        ssize_t w = write(fd, p, n);
        if (w <= 0) die("write failed");
        p += w;
        n -= w;
    }
}

static size_t pagesz(void) {
    static size_t ps = 0;
    if (!ps) ps = sysconf(_SC_PAGESIZE);
    return ps;
}

#define PAGE_DOWN(v) ((v) & ~(pagesz() - 1))
#define PAGE_UP(v)   (((v) + pagesz() - 1) & ~(pagesz() - 1))

/* ── Find wrapper's own ELF end ──────────────────────────────────────────── */

static size_t find_elf_end(const uint8_t *data, size_t len) {
    if (len < sizeof(Elf64_Ehdr)) die("ELF too small");
    const Elf64_Ehdr *eh = (const Elf64_Ehdr *)data;
    if (memcmp(eh->e_ident, ELFMAG, SELFMAG) || eh->e_ident[EI_CLASS] != ELFCLASS64)
        die("not ELF64");

    size_t end = 0;
    for (int i = 0; i < eh->e_phnum; i++) {
        const Elf64_Phdr *ph = (const Elf64_Phdr *)(data + eh->e_phoff + i * eh->e_phentsize);
        if (ph->p_type == PT_LOAD) {
            size_t s = ph->p_offset + ph->p_filesz;
            if (s > end) end = s;
        }
    }
    if (eh->e_shoff && eh->e_shnum) {
        size_t s = eh->e_shoff + (size_t)eh->e_shentsize * eh->e_shnum;
        if (s > end) end = s;
    }
    return end;
}

/* ── FNV-1a hash ─────────────────────────────────────────────────────────── */

static uint64_t fnv1a(const uint8_t *data, size_t len) {
    uint64_t h = 0xcbf29ce484222325ULL;
    for (size_t i = 0; i < len; i++) {
        h ^= data[i];
        h *= 0x100000001b3ULL;
    }
    return h;
}

/* ── Cache helpers ───────────────────────────────────────────────────────── */

static void get_cache_dir(char *out, size_t out_len) {
    const char *tmpdir = getenv("TMPDIR");
    if (!tmpdir) tmpdir = "/data/data/com.termux/files/usr/tmp";
    snprintf(out, out_len, "%s/bun-termux-cache", tmpdir);
    mkdir(out, 0755);
}

static void extract_to_cache(const uint8_t *data, size_t size,
                             const char *cache_dir, const char *name,
                             char *out, size_t out_len) {
    snprintf(out, out_len, "%s/%s", cache_dir, name);

    struct stat st;
    if (stat(out, &st) == 0 && (size_t)st.st_size == size)
        return;

    char tmp[512];
    snprintf(tmp, sizeof(tmp), "%s/.%s.tmp", cache_dir, name);

    int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, 0755);
    if (fd < 0) die("cache create failed");
    write_all(fd, data, size);
    close(fd);

    if (rename(tmp, out) != 0) die("cache rename failed");
}

/* ── Bun ELF cache (hash-based) ──────────────────────────────────────────── */

static void cache_bun_elf(const uint8_t *elf, size_t size,
                          const char *cache_dir, char *out, size_t out_len) {
    /* Use first 64KB + last 64KB + size for cache key */
    /* This avoids cache collision when versions share identical headers */
    size_t sample = size < 65536 ? size : 65536;
    size_t last_sample = sample;
    if (size < last_sample) last_sample = size;
    size_t key_sz = sample + last_sample + 8;
    uint8_t *key = malloc(key_sz);
    if (!key) die("malloc");
    memcpy(key, elf, sample);
    memcpy(key + sample, elf + size - last_sample, last_sample);
    memcpy(key + sample + last_sample, &size, 8);
    uint64_t hash = fnv1a(key, key_sz);
    free(key);

    char name[64];
    snprintf(name, sizeof(name), "bun-%016llx", (unsigned long long)hash);
    extract_to_cache(elf, size, cache_dir, name, out, out_len);
}

/* ── Userland exec ───────────────────────────────────────────────────────── */

__attribute__((noreturn))
static void userland_exec(const char *ldso, const char **argv, size_t argc,
                          const char **envp, size_t envc) {
    int fd = open(ldso, O_RDONLY);
    if (fd < 0) die("open ld.so failed");

    struct stat st;
    fstat(fd, &st);

    uint8_t *fdata = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (fdata == MAP_FAILED) die("mmap ld.so failed");

    const Elf64_Ehdr *eh = (const Elf64_Ehdr *)fdata;
    if (memcmp(eh->e_ident, ELFMAG, SELFMAG)) die("ld.so not ELF");

    /* Find virtual address range */
    size_t vmin = (size_t)-1, vmax = 0;
    for (int i = 0; i < eh->e_phnum; i++) {
        const Elf64_Phdr *ph = (const Elf64_Phdr *)(fdata + eh->e_phoff + i * eh->e_phentsize);
        if (ph->p_type == PT_LOAD) {
            if (ph->p_vaddr < vmin) vmin = ph->p_vaddr;
            size_t e = ph->p_vaddr + ph->p_memsz;
            if (e > vmax) vmax = e;
        }
    }
    vmin = PAGE_DOWN(vmin);
    vmax = PAGE_UP(vmax);

    /* Reserve region */
    uint8_t *base = mmap(NULL, vmax - vmin, PROT_NONE, MAP_PRIVATE | MAP_ANON, -1, 0);
    if (base == MAP_FAILED) die("reserve failed");

    /* Map segments */
    for (int i = 0; i < eh->e_phnum; i++) {
        const Elf64_Phdr *ph = (const Elf64_Phdr *)(fdata + eh->e_phoff + i * eh->e_phentsize);
        if (ph->p_type != PT_LOAD) continue;

        size_t off_a  = PAGE_DOWN(ph->p_offset);
        size_t va_a   = PAGE_DOWN(ph->p_vaddr);
        size_t diff   = ph->p_offset - off_a;
        size_t mapsz  = PAGE_UP(ph->p_filesz + diff);

        int prot = 0;
        if (ph->p_flags & PF_R) prot |= PROT_READ;
        if (ph->p_flags & PF_W) prot |= PROT_WRITE;
        if (ph->p_flags & PF_X) prot |= PROT_EXEC;

        void *seg = mmap(base + va_a - vmin, mapsz, prot | PROT_WRITE,
                         MAP_PRIVATE | MAP_FIXED, fd, off_a);
        if (seg == MAP_FAILED) die("segment map failed");

        /* BSS */
        if (ph->p_memsz > ph->p_filesz) {
            uint8_t *bss = base + (ph->p_vaddr - vmin) + ph->p_filesz;
            size_t bsz = ph->p_memsz - ph->p_filesz;
            size_t in_page = PAGE_UP((size_t)bss) - (size_t)bss;
            if (in_page > bsz) in_page = bsz;
            memset(bss, 0, in_page);
            if (bsz > in_page) {
                void *a = mmap(bss + in_page, PAGE_UP(bsz - in_page),
                               prot | PROT_WRITE, MAP_PRIVATE | MAP_ANON | MAP_FIXED, -1, 0);
                if (a == MAP_FAILED) die("BSS map failed");
            }
        }

        if (!(ph->p_flags & PF_W))
            mprotect(seg, mapsz, prot);
    }

    size_t base_addr = (size_t)base - vmin;
    size_t entry = base_addr + eh->e_entry;

    /* AT_PHDR from PT_PHDR */
    size_t phdr_addr = 0;
    for (int i = 0; i < eh->e_phnum; i++) {
        const Elf64_Phdr *ph = (const Elf64_Phdr *)(fdata + eh->e_phoff + i * eh->e_phentsize);
        if (ph->p_type == PT_PHDR) { phdr_addr = base_addr + ph->p_vaddr; break; }
    }
    if (!phdr_addr) {
        for (int i = 0; i < eh->e_phnum; i++) {
            const Elf64_Phdr *ph = (const Elf64_Phdr *)(fdata + eh->e_phoff + i * eh->e_phentsize);
            if (ph->p_type == PT_LOAD) {
                phdr_addr = base_addr + ph->p_vaddr + eh->e_phoff;
                break;
            }
        }
    }

    uint16_t phnum = eh->e_phnum;
    uint16_t phent = eh->e_phentsize;
    munmap(fdata, st.st_size);
    close(fd);

    /* ── Build stack ─────────────────────────────────────────────────────── */

    size_t stksz = 10 * 1024 * 1024;
    uint8_t *stk = mmap(NULL, stksz, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANON | MAP_STACK, -1, 0);
    if (stk == MAP_FAILED) die("stack alloc failed");

    uint8_t *sp = stk + stksz;

    /* Push helpers (stack grows down) */
    #define PUSH_BYTES(src, n) do { sp -= (n); memcpy(sp, (src), (n)); } while(0)
    #define PUSH_STR(s) ({ size_t _l = strlen(s)+1; sp -= _l; memcpy(sp, s, _l); (size_t)sp; })
    #define PUSH_VAL(v) do { size_t _v = (v); sp -= 8; memcpy(sp, &_v, 8); } while(0)

    /* Strings at top of stack */
    size_t plat_addr = PUSH_STR("aarch64");

    uint8_t rnd[16];
    int ufd = open("/dev/urandom", O_RDONLY);
    if (ufd >= 0) { read(ufd, rnd, 16); close(ufd); }
    else memset(rnd, 0x42, 16);
    sp -= 16; memcpy(sp, rnd, 16);
    size_t rnd_addr = (size_t)sp;

    /* Push argv strings, save addresses */
    size_t argv_a[MAX_ARGS];
    for (size_t i = 0; i < argc; i++)
        argv_a[i] = PUSH_STR(argv[i]);
    size_t execfn = argc ? argv_a[0] : 0;

    /* Push envp strings */
    size_t envp_a[MAX_ENV];
    for (size_t i = 0; i < envc; i++)
        envp_a[i] = PUSH_STR(envp[i]);

    /* Auxv */
    size_t auxv[][2] = {
        { AT_PHDR,         phdr_addr },
        { AT_PHENT,        phent },
        { AT_PHNUM,        phnum },
        { AT_PAGESZ,       pagesz() },
        { AT_BASE,         base_addr },
        { AT_FLAGS,        0 },
        { AT_ENTRY,        entry },
        { AT_UID,          getuid() },
        { AT_EUID,         geteuid() },
        { AT_GID,          getgid() },
        { AT_EGID,         getegid() },
        { AT_HWCAP,        getauxval(AT_HWCAP) },
        { AT_HWCAP2,       getauxval(AT_HWCAP2) },
        { AT_CLKTCK,       sysconf(_SC_CLK_TCK) },
        { AT_RANDOM,       rnd_addr },
        { AT_SECURE,       getauxval(AT_SECURE) },
        { AT_SYSINFO_EHDR, getauxval(AT_SYSINFO_EHDR) },
        { AT_EXECFN,       execfn },
        { AT_PLATFORM,     plat_addr },
        { AT_NULL,         0 },
    };
    size_t auxc = sizeof(auxv) / sizeof(auxv[0]);

    /* Calculate total words and align */
    size_t nwords = 1 + (argc + 1) + (envc + 1) + auxc * 2;
    size_t data_sz = nwords * 8;
    sp = (uint8_t *)(((size_t)sp - data_sz) & ~(size_t)15);

    /* Write stack: argc, argv ptrs, NULL, envp ptrs, NULL, auxv */
    size_t *w = (size_t *)sp;
    *w++ = argc;
    for (size_t i = 0; i < argc; i++) *w++ = argv_a[i];
    *w++ = 0;
    for (size_t i = 0; i < envc; i++) *w++ = envp_a[i];
    *w++ = 0;
    for (size_t i = 0; i < auxc; i++) { *w++ = auxv[i][0]; *w++ = auxv[i][1]; }

    /* ── Jump ────────────────────────────────────────────────────────────── */

    __asm__ volatile(
        "mov sp, %[sp]\n"
        "mov x0, sp\n"
        "mov x1, xzr\n"
        "mov x2, xzr\n"
        "mov x3, xzr\n"
        "mov x4, xzr\n"
        "mov x5, xzr\n"
        "mov x30, xzr\n"
        "br  %[entry]\n"
        :
        : [sp] "r"((size_t)sp), [entry] "r"(entry)
        : "x0","x1","x2","x3","x4","x5","x30","memory"
    );
    __builtin_unreachable();
}

/* ── Main ────────────────────────────────────────────────────────────────── */

int main(int argc, char **argv, char **envp) {
    char self_path[4096];
    ssize_t rl = readlink("/proc/self/exe", self_path, sizeof(self_path)-1);
    if (rl < 0) die("readlink /proc/self/exe failed");
    self_path[rl] = 0;
    int fd = open(self_path, O_RDONLY);
    if (fd < 0) die("open self failed");

    /* Read ELF headers */
    uint8_t hdr[64];
    read_all(fd, hdr, 64);
    const Elf64_Ehdr *eh = (const Elf64_Ehdr *)hdr;

    size_t need = 64;
    size_t pe = eh->e_phoff + (size_t)eh->e_phentsize * eh->e_phnum;
    size_t se = eh->e_shoff + (size_t)eh->e_shentsize * eh->e_shnum;
    if (pe > need) need = pe;
    if (se > need) need = se;

    uint8_t *hdrs = malloc(need);
    if (!hdrs) die("malloc");
    lseek(fd, 0, SEEK_SET);
    read_all(fd, hdrs, need);
    size_t wend = find_elf_end(hdrs, need);
    free(hdrs);

    /* Read BUNWRAP1 metadata */
    uint8_t meta[16];
    lseek(fd, wend, SEEK_SET);
    read_all(fd, meta, 16);

    if (memcmp(meta, "BUNWRAP1", 8) != 0) {
        die("no embedded Bun runtime (missing BUNWRAP1)");
    }

    uint64_t bun_sz;
    memcpy(&bun_sz, meta + 8, 8);

    uint8_t *bun = malloc(bun_sz);
    if (!bun) die("malloc bun");
    read_all(fd, bun, bun_sz);

    /* Cache dir */
    char cache_dir[512];
    get_cache_dir(cache_dir, sizeof(cache_dir));

    /* Cache Bun ELF */
    char cached_bun[512];
    cache_bun_elf(bun, bun_sz, cache_dir, cached_bun, sizeof(cached_bun));
    free(bun);

    /* ── Read BUNLIBS metadata (native libs + shim) ──────────────────────── */
    /*
     * Format after Bun ELF:
     *   "BUNLIBS1" (8 bytes)
     *   num_libs   (4 bytes LE)
     *   For each lib:
     *     name_len (2 bytes LE)
     *     name     (name_len bytes, not null-terminated)
     *     data_len (8 bytes LE)
     *     data     (data_len bytes)
     *   After all libs: embedded JS + Bun trailer continues
     */

    char bunfs_dir[512];
    snprintf(bunfs_dir, sizeof(bunfs_dir), "%s/bunfs-libs", cache_dir);

    char shim_path[512];
    shim_path[0] = '\0';
    int has_shim = 0;

    uint8_t libs_magic[8];
    ssize_t rd = read(fd, libs_magic, 8);
    if (rd == 8 && memcmp(libs_magic, "BUNLIBS1", 8) == 0) {
        mkdir(bunfs_dir, 0755);

        uint32_t num_libs;
        read_all(fd, &num_libs, 4);

        for (uint32_t i = 0; i < num_libs && i < MAX_LIBS; i++) {
            uint16_t name_len;
            read_all(fd, &name_len, 2);

            char name[256];
            if (name_len >= sizeof(name)) die("lib name too long");
            read_all(fd, name, name_len);
            name[name_len] = '\0';

            uint64_t data_len;
            read_all(fd, &data_len, 8);

            uint8_t *lib_data = malloc(data_len);
            if (!lib_data) die("malloc lib");
            read_all(fd, lib_data, data_len);

            char lib_path[512];
            extract_to_cache(lib_data, data_len, bunfs_dir, name,
                             lib_path, sizeof(lib_path));
            free(lib_data);

            if (strcmp(name, "bunfs_shim.so") == 0) {
                snprintf(shim_path, sizeof(shim_path), "%s", lib_path);
                has_shim = 1;
            }
        }
    }

    close(fd);

    /* Build argv for ld.so */
    const char *new_argv[MAX_ARGS];
    size_t na = 0;
    new_argv[na++] = LD_SO;
    if (has_shim) {
        new_argv[na++] = "--preload";
        new_argv[na++] = shim_path;
    }
    new_argv[na++] = "--library-path";
    new_argv[na++] = GLIBC_LIB;
    new_argv[na++] = cached_bun;
    for (int i = 1; i < argc && na < MAX_ARGS; i++)
        new_argv[na++] = argv[i];

    /* Filter envp, add BUNFS_CACHE_DIR if shim present */
    static char bunfs_env[512];
    snprintf(bunfs_env, sizeof(bunfs_env), "BUNFS_CACHE_DIR=%s", bunfs_dir);

    const char *new_envp[MAX_ENV];
    size_t ne = 0;
    for (char **e = envp; *e && ne < MAX_ENV; e++) {
        if (strncmp(*e, "LD_PRELOAD=", 11) == 0) continue;
        if (strncmp(*e, "LD_LIBRARY_PATH=", 16) == 0) continue;
        new_envp[ne++] = *e;
    }
    if (has_shim && ne < MAX_ENV)
        new_envp[ne++] = bunfs_env;

    userland_exec(LD_SO, new_argv, na, new_envp, ne);
}
