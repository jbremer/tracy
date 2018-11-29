/*
    This file is part of Tracy.

    Tracy is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Tracy is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Tracy.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <fcntl.h>
#include <asm/ioctls.h>
#include <linux/futex.h>
#include "tracy.h"
#include "tracyarch.h"

#define MAXPATH 1023
#define MAXFD 1023

#define dprintf(...) \
    if(g_verbose != 0) printf(__VA_ARGS__)

static const char *g_filepath;
static const char *g_dirpath;
static int g_dirpath_length;
static int g_verbose;
static int g_max_clones;
static uint64_t g_max_write = 1024 * 1024 * 1024; // One GB.

static const char *g_syscall_allowed[] = {
    "read", "lseek", "stat", "fstat", "umask", "lstat", "utimensat",
    "exit_group", "fchmod", "utime", "getdents", "chmod", "munmap", "time",
    "rt_sigaction", "brk", "fcntl", "access", "getcwd", "chdir", "select",
    NULL,
};

static const char *g_openat_allowed[] = {
    "/sys/devices/system/cpu",
    NULL,
};

static const char *g_open_mmap_rx_allowed[] = {
    "/lib/x86_64-linux-gnu/libnsl.so.1",
    "/lib/x86_64-linux-gnu/libnss_compat.so.2",
    "/lib/x86_64-linux-gnu/libnss_files.so.2",
    "/lib/x86_64-linux-gnu/libnss_nis.so.2",
    NULL,
};

static const char *g_open_mmap_r_shared_allowed[] = {
    "/etc/passwd",
    "/etc/group",
    NULL,
};

typedef enum {
    FD_SOCKET = 1,
    FD_MMAP_RX = 2,
    FD_MMAP_R_SHARED = 4,
    FD_DIRFD = 8,
} fd_t;

static int g_fds[MAXFD+1];

static const char *read_path(
    struct tracy_event *e, const char *function, uintptr_t addr)
{
    static char path[MAXPATH+1];

    if(tracy_read_mem(e->child, path, (void *) addr, MAXPATH+1) < 0 ||
            memchr(path, 0, MAXPATH+1) == NULL) {
        fprintf(stderr,
            "Invalid path for %s(2) while in sandbox mode!\n"
            "ip=%p sp=%p abi=%ld\n",
            function, (void *) e->args.ip, (void *) e->args.sp, e->abi
        );
        return NULL;
    }

    return path;
}

static int check_path(const char *filepath)
{
    const char *ptr = strstr(filepath, "..");
    if(ptr != NULL && (ptr[2] == '/' || ptr[2] == '\\')) {
        fprintf(stderr,
            "Detected potential directory traversal arbitrary overwrite!\n"
            "filepath=%s\n", filepath
        );
        return -1;
    }

    if(strcmp(filepath, g_filepath) == 0) {
        return 0;
    }

    if(strcmp(filepath, g_dirpath) == 0) {
        return 0;
    }

    // Allow relative paths too, e.g., for openat(2) and mkdirat(2).
    if(filepath[0] == '/' && (
            strncmp(filepath, g_dirpath, strlen(g_dirpath)) != 0 ||
            filepath[g_dirpath_length] != '/')) {
        fprintf(stderr,
            "Detected potential out-of-path arbitrary overwrite!\n"
            "filepath=%s dirpath=%s\n", filepath, g_dirpath
        );
        return -1;
    }

    return 0;
}

static int check_path2(const char *filepath)
{
    char linkpath[MAXPATH+1]; struct stat st; int length;

    if(lstat(filepath, &st) < 0) {
        if(errno != ENOENT) {
            fprintf(stderr, "Unknown lstat() errno: %d\n", errno);
            return -1;
        }
    }
    else if(S_ISLNK(st.st_mode) != 0) {
        length = readlink(filepath, linkpath, sizeof(linkpath)-1);
        linkpath[length >= 0 ? length : 0] = 0;

        fprintf(stderr,
            "Detected potential symlink-based arbitrary overwrite!\n"
            "filepath=%s realpath=%s\n", filepath, linkpath
        );
        return -1;
    }

    return check_path(filepath);
}

static int _sandbox_open(struct tracy_event *e)
{
    const char *filepath = read_path(e, "open", e->args.a0);
    if(filepath == NULL) {
        return TRACY_HOOK_ABORT;
    }

    // We allow tar(1) to mmap(RX) some memory.
    for (const char **p = g_open_mmap_rx_allowed; *p != NULL; p++) {
        if((e->args.a1 & O_ACCMODE) == O_RDONLY &&
                e->child->pre_syscall == 0 &&
                strcmp(filepath, *p) == 0) {
            g_fds[e->args.return_code] = FD_MMAP_RX;
        }
    }

    // We allow tar(1) to mmap(R, MAP_SHARED) some memory.
    for (const char **p = g_open_mmap_r_shared_allowed; *p != NULL; p++) {
        if((e->args.a1 & O_ACCMODE) == O_RDONLY &&
                e->child->pre_syscall == 0 &&
                strcmp(filepath, *p) == 0) {
            g_fds[e->args.return_code] = FD_MMAP_R_SHARED;
        }
    }

    // We accept open(..., O_RDONLY).
    if((e->args.a1 & O_ACCMODE) == O_RDONLY) {
        return TRACY_HOOK_CONTINUE;
    }

    dprintf("open(%s, %lx, %ld)\n", filepath, e->args.a1, e->args.a2);

    if(check_path2(filepath) < 0) {
        return TRACY_HOOK_ABORT;
    }

    return TRACY_HOOK_CONTINUE;
}

static int _sandbox_openat(struct tracy_event *e)
{
    if(e->args.a0 != AT_FDCWD && (
            e->args.a0 >= 0 && e->args.a0 < MAXFD+1 &&
            g_fds[e->args.a0] == FD_DIRFD) == 0) {
        fprintf(stderr,
            "Invalid dirfd provided for openat(2) while in sandbox mode!\n"
            "ip=%p sp=%p abi=%ld\n",
            (void *) e->args.ip, (void *) e->args.sp, e->abi
        );
        return TRACY_HOOK_ABORT;
    }

    if((e->args.a2 & O_ACCMODE) == O_RDONLY) {
        if(e->child->pre_syscall == 0 && e->args.return_code >= 0 &&
                e->args.return_code < MAXFD+1) {
            g_fds[e->args.return_code] = FD_DIRFD;
        }
        return TRACY_HOOK_CONTINUE;
    }

    const char *filepath = read_path(e, "openat", e->args.a1);
    if(filepath == NULL) {
        return TRACY_HOOK_ABORT;
    }

    dprintf("openat(%ld, %s)\n", e->args.a0, filepath);

    for (const char **ptr = g_openat_allowed; *ptr != NULL; ptr++) {
        if(strcmp(filepath, *ptr) == 0) {
            return TRACY_HOOK_CONTINUE;
        }
    }

    if(check_path2(filepath) < 0) {
        return TRACY_HOOK_ABORT;
    }

    return TRACY_HOOK_CONTINUE;
}

static int _sandbox_unlink(struct tracy_event *e)
{
    const char *filepath = read_path(e, "unlink", e->args.a0);
    if(filepath == NULL) {
        return TRACY_HOOK_ABORT;
    }

    dprintf("unlink(%s)\n", filepath);

    if(check_path2(filepath) < 0) {
        return TRACY_HOOK_ABORT;
    }

    return TRACY_HOOK_CONTINUE;
}

static int _sandbox_unlinkat(struct tracy_event *e)
{
    if(e->args.a0 < 0 || e->args.a0 > MAXFD ||
            g_fds[e->args.a0] != FD_DIRFD) {
        return TRACY_HOOK_ABORT;
    }

    const char *filepath = read_path(e, "unlinkat", e->args.a1);
    if(filepath == NULL) {
        return TRACY_HOOK_ABORT;
    }

    if(check_path2(filepath) < 0) {
        return TRACY_HOOK_ABORT;
    }

    return TRACY_HOOK_CONTINUE;
}

static int _sandbox_mkdir(struct tracy_event *e)
{
    const char *dirpath = read_path(e, "mkdir", e->args.a0);
    if(dirpath == NULL) {
        return TRACY_HOOK_ABORT;
    }

    dprintf("mkdir(%s)\n", dirpath);

    // If the directory already exists we can just ignore this call anyway.
    struct stat st;
    if(lstat(dirpath, &st) == 0) {
        return TRACY_HOOK_CONTINUE;
    }

    if(*dirpath == 0 || check_path(dirpath) == 0) {
        return TRACY_HOOK_CONTINUE;
    }

    return TRACY_HOOK_ABORT;
}

static int _sandbox_mkdirat(struct tracy_event *e)
{
    if(e->args.a0 < 0 || e->args.a0 > MAXFD ||
            g_fds[e->args.a0] != FD_DIRFD) {
        return TRACY_HOOK_ABORT;
    }

    const char *dirpath = read_path(e, "mkdirat", e->args.a1);
    if(dirpath == NULL) {
        return TRACY_HOOK_ABORT;
    }

    // If the directory already exists we can just ignore this call anyway.
    struct stat st;
    if(dirpath[0] == '/' && lstat(dirpath, &st) == 0) {
        return TRACY_HOOK_CONTINUE;
    }

    if(*dirpath == 0 || check_path(dirpath) == 0) {
        return TRACY_HOOK_CONTINUE;
    }

    return TRACY_HOOK_ABORT;
}

static int _sandbox_readlink(struct tracy_event *e)
{
    const char *filepath = read_path(e, "readlink", e->args.a0);
    if(filepath == NULL) {
        return TRACY_HOOK_ABORT;
    }

    dprintf("readlink(%s)\n", filepath);

    if(check_path(filepath) == 0) {
        return TRACY_HOOK_CONTINUE;
    }

    return TRACY_HOOK_ABORT;
}

static int _sandbox_mmap(struct tracy_event *e)
{
    if(e->args.a4 >= 0 && e->args.a4 < MAXFD+1) {
        if((g_fds[e->args.a4] & FD_MMAP_RX) != 0 &&
                (e->args.a2 & PROT_EXEC) == PROT_EXEC) {
            return TRACY_HOOK_CONTINUE;
        }

        if((g_fds[e->args.a4] & FD_MMAP_R_SHARED) != 0 &&
                (e->args.a3 & MAP_SHARED) == MAP_SHARED) {
            return TRACY_HOOK_CONTINUE;
        }
    }

    if((e->args.a2 & PROT_EXEC) == PROT_EXEC) {
        fprintf(stderr,
            "Blocked mmap(2) syscall with X flag set!\n"
        );
        return TRACY_HOOK_ABORT;
    }
    if((e->args.a3 & MAP_SHARED) == MAP_SHARED) {
        fprintf(stderr,
            "Blocked mmap(2) syscall with MAP_SHARED flag set!\n"
        );
        return TRACY_HOOK_ABORT;
    }
    return TRACY_HOOK_CONTINUE;
}

static int _sandbox_mprotect(struct tracy_event *e)
{
    if((e->args.a2 & PROT_EXEC) == PROT_EXEC) {
        fprintf(stderr,
            "Blocked mprotect(2) syscall with X flag set!\n"
        );
        return TRACY_HOOK_ABORT;
    }
    return TRACY_HOOK_CONTINUE;
}

static int _sandbox_ioctl(struct tracy_event *e)
{
    dprintf("ioctl(%ld, %ld, 0x%lx)\n", e->args.a0, e->args.a1, e->args.a2);

    if(e->args.a0 == 1 && e->args.a1 == TIOCGWINSZ) {
        return TRACY_HOOK_CONTINUE;
    }

    if(e->args.a1 == TCGETS || e->args.a1 == TCSETS) {
        return TRACY_HOOK_CONTINUE;
    }

    return TRACY_HOOK_ABORT;
}

static int _sandbox_futex(struct tracy_event *e)
{
    dprintf("futex(%ld, %ld, 0x%lx)\n", e->args.a0, e->args.a1, e->args.a2);

    switch (e->args.a1) {
    case FUTEX_WAIT:
    case FUTEX_PRIVATE_FLAG:
    case FUTEX_WAKE_PRIVATE:
    case FUTEX_CMP_REQUEUE_PRIVATE:
        return TRACY_HOOK_CONTINUE;
    }

    return TRACY_HOOK_ABORT;
}

static int _sandbox_clone(struct tracy_event *e)
{
    static int clone_count = 0;
    dprintf("clone(0x%lx, ...)\n", e->args.a0);
    if(e->child->pre_syscall == 1 && clone_count++ == g_max_clones) {
        return TRACY_HOOK_ABORT;
    }
    return TRACY_HOOK_CONTINUE;
}

static int _sandbox_write(struct tracy_event *e)
{
    static uint64_t written = 0;

    if(e->child->pre_syscall == 0) {
        return TRACY_HOOK_CONTINUE;
    }

    if(written + e->args.a2 < written ||
            written + e->args.a2 >= g_max_write) {
        fprintf(stderr, "Excessive writing caused incomplete unpacking!\n");
        return TRACY_HOOK_ABORT;
    }

    written += e->args.a2;
    return TRACY_HOOK_CONTINUE;
}

static int _sandbox_socket(struct tracy_event *e)
{
    if(e->args.a0 != AF_LOCAL ||
            e->args.a1 != (SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK) ||
            e->args.a2 != 0) {
        fprintf(stderr, "Blocking non-AF_LOCAL socket(2) call!\n");
        return TRACY_HOOK_ABORT;
    }
    if(e->child->pre_syscall == 0) {
        g_fds[e->args.return_code] = FD_SOCKET;
    }
    return TRACY_HOOK_CONTINUE;
}

static int _sandbox_connect(struct tracy_event *e)
{
    static struct sockaddr_un sa;

    if(e->args.a0 < 0 || e->args.a0 > MAXFD ||
            g_fds[e->args.a0] != FD_SOCKET) {
        fprintf(stderr, "Invalid fd for connect(2) call!\n");
        return TRACY_HOOK_ABORT;
    }

    if(e->args.a2 != sizeof(struct sockaddr_un)) {
        fprintf(stderr, "Invalid sockaddr_un struct for connect(2) call!\n");
        return TRACY_HOOK_ABORT;
    }

    if(tracy_read_mem(e->child, &sa, (void *) e->args.a1,
            sizeof(struct sockaddr_un)) < 0) {
        fprintf(stderr, "Invalid sockaddr_un struct for connect(2) call!\n");
        return TRACY_HOOK_ABORT;
    }

    if(strcmp(sa.sun_path, "/var/run/nscd/socket") != 0) {
        return TRACY_HOOK_ABORT;
    }

    return TRACY_HOOK_CONTINUE;
}

static int _sandbox_close(struct tracy_event *e)
{
    if(e->child->pre_syscall == 1) {
        g_fds[e->args.a0] = 0;
    }
    return TRACY_HOOK_CONTINUE;
}

static int _sandbox_allow(struct tracy_event *e)
{
    (void) e;
    return TRACY_HOOK_CONTINUE;
}

static int _zipjail_block(struct tracy_event *e)
{
    const char *syscall = get_syscall_name_abi(e->args.syscall, e->abi);

    fprintf(stderr,
        "Blocked system call occurred during sandboxing!\n"
        "ip=%p sp=%p abi=%ld nr=%ld syscall=%s\n",
        (void *) e->args.ip, (void *) e->args.sp,
        e->abi, e->args.syscall, syscall
    );

    return TRACY_HOOK_ABORT;
}

#define H(name) \
    if(tracy_set_hook(e->child->tracy, #name, e->abi, &_sandbox_##name) < 0) { \
        fprintf(stderr, "Error setting %s(2) sandbox hook!\n", #name); \
        return TRACY_HOOK_ABORT; \
    }

static int _zipjail_enter_sandbox(struct tracy_event *e)
{
    if(tracy_unset_hook(e->child->tracy, "open", e->abi) < 0) {
        fprintf(stderr, "Error unsetting open trigger hook!\n");
        return TRACY_HOOK_ABORT;
    }

    H(open); H(openat); H(unlink); H(mkdir); H(readlink); H(mmap);
    H(mprotect); H(ioctl); H(futex); H(clone); H(write); H(socket);
    H(connect); H(close); H(mkdirat); H(unlinkat);

    for (const char **sc = g_syscall_allowed; *sc != NULL; sc++) {
        if(tracy_set_hook(e->child->tracy, *sc, e->abi,
                &_sandbox_allow) < 0) {
            fprintf(stderr,
                "Error setting allowed sandbox syscall: %s!\n", *sc
            );
            return TRACY_HOOK_ABORT;
        }
    }

    if(tracy_set_default_hook(e->child->tracy, &_zipjail_block) < 0) {
        fprintf(stderr, "Error setting generic sandbox hook!\n");
        return TRACY_HOOK_ABORT;
    }

    return TRACY_HOOK_CONTINUE;
}

static int _trigger_open(struct tracy_event *e)
{
    const char *filepath = read_path(e, "open", e->args.a0);
    if(filepath == NULL) {
        return TRACY_HOOK_ABORT;
    }

    dprintf("open(%s)\n", filepath);

    // Enter sandboxing mode.
    if(strcmp(filepath, g_filepath) == 0) {
        return _zipjail_enter_sandbox(e);
    }

    return TRACY_HOOK_CONTINUE;
}

int main(int argc, char *argv[])
{
    if(argc < 4) {
        fprintf(stderr,
            "zipjail 0.4.1 - safe unpacking of potentially unsafe archives.\n"
            "Copyright (C) 2016-2018, Jurriaan Bremer <jbr@cuckoo.sh>.\n"
            "Copyright (C) 2018, Hatching B.V.\n"
            "Based on Tracy by Merlijn Wajer and Bas Weelinck.\n"
            "    (https://github.com/MerlijnWajer/tracy)\n"
            "\n"
            "Usage: %s <input> <output> [options...] -- <command...>\n"
            "  input:   input archive file\n"
            "  output:  directory to extract files to\n"
            "  verbose: some verbosity\n"
            "\n"
            "Options:\n"
            "  -v           more verbosity\n"
            "  -a=X         terminates process after X seconds\n"
            "  --alarm=X    same as -a=X\n"
            "  -c=N         more clones (default: 0)\n"
            "  --clone=N    same as -c=N\n"
            "  -w=X         maximum total file size (default: 1GB)\n"
            "  --write=X    same as -w=X\n"
            "\n"
            "Please refer to the README for the exact usage.\n",
            argv[0]
        );
        return 1;
    }

    g_filepath = *++argv;
    g_dirpath = *++argv;
    g_dirpath_length = strlen(g_dirpath);

    uint32_t alarm_seconds = 120;

    while (*++argv != NULL && strcmp(*argv, "--") != 0) {
        if(strcmp(*argv, "-v") == 0) {
            g_verbose = 1;
        }
        else if(strncmp(*argv, "-a=", 3) == 0) {
            alarm_seconds = strtoul(*argv + 3, NULL, 10);
        }
        else if(strncmp(*argv, "--alarm=", 8) == 0) {
            alarm_seconds = strtoul(*argv + 8, NULL, 10);
        }
        else if(strncmp(*argv, "-c=", 3) == 0) {
            g_max_clones = strtoul(*argv + 3, NULL, 10);
        }
        else if(strncmp(*argv, "--clone=", 8) == 0) {
            g_max_clones = strtoul(*argv + 8, NULL, 10);
        }
        else if(strncmp(*argv, "-w=", 3) == 0) {
            g_max_write = strtoul(*argv + 3, NULL, 10);
        }
        else if(strncmp(*argv, "--write=", 8) == 0) {
            g_max_write = strtoul(*argv + 8, NULL, 10);
        }
        else {
            fprintf(stderr, "Error parsing command-line option!\n");
            return -1;
        }
    }

    // This happens when no "--" separator has been used.
    if(*argv == NULL) {
        fprintf(stderr, "Error parsing command-line!\n");
        return -1;
    }

    // Terminate zipjail after X seconds (default 120).
    alarm(alarm_seconds);

    // We create the target directory just in case it does not already exist.
    // Without a dirpath that actually exists, unrar would otherwise unpack to
    // the current directory rather than our expected dirpath.
    mkdir(g_dirpath, 0775);

    struct tracy *tracy = tracy_init(0);

#if __x86_64__
    if(tracy_set_hook(tracy, "open", TRACY_ABI_AMD64, &_trigger_open) < 0) {
        fprintf(stderr, "Error hooking open(2)\n");
        return -1;
    }
#endif

    if(tracy_set_hook(tracy, "open", TRACY_ABI_X86, &_trigger_open) < 0) {
        fprintf(stderr, "Error hooking open(2)\n");
        return -1;
    }

    tracy_exec(tracy, ++argv);
    tracy_main(tracy);
    tracy_free(tracy);
    return 0;
}
