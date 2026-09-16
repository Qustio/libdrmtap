/*
 * libdrmtap — DRM/KMS screen capture library for Linux
 * https://github.com/fxd0h/libdrmtap
 *
 * Copyright (c) 2026 Mariano Abad <weimaraner@gmail.com>
 * SPDX-License-Identifier: MIT
 */

/**
 * @file server.c
 * @brief Implementation of the root-hosted capture serverusing sockets (drmtap_server.h).
 *
 * Everything that touches the capture context (drmtap_open/grab_desc/close)
 * runs on ONE internal worker thread for the server's whole lifetime — the
 * open happens there too, not in drmtap_server_start()'s caller thread —
 * so there is never a cross-thread handoff of the context, matching the
 * same-thread discipline drmtap.h documents for drmtap_convert_dmabuf's
 * render contexts even though a plain KMS capture context does not use EGL.
 * drmtap_server_start() blocks (via a condvar) until that thread finishes
 * opening the device and binding the socket, so a NULL return means startup
 * genuinely failed and nothing was left running.
 *
 * Only one connection is served at a time (accept, serve until disconnect,
 * accept again) — this server has exactly one intended consumer, so there is
 * no RustDesk-style multi-connection/credit-flow-control machinery here.
 */

#define _GNU_SOURCE
#include "drmtap_server.h"
#include "server_wire.h"
#include "wire.h"
#include "drmtap.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <unistd.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/prctl.h>
#include <linux/dma-buf.h>
#ifdef HAVE_LIBCAP
#include <sys/capability.h>
#endif
#ifdef HAVE_SECCOMP
#include <malloc.h>
#include <seccomp.h>
#endif

/* ========================================================================= */
/* Security hardening                                                        */
/* ========================================================================= */

#ifdef HAVE_LIBCAP
// Drop all capabilities except CAP_SYS_ADMIN
static int drop_caps(void) {
    cap_t caps = cap_init();
    if (!caps) {
        perror("drmtap-helper: cap_init failed"); return -1;
    }

    cap_value_t keep[] = { CAP_SYS_ADMIN };
    if (cap_set_flag(caps, CAP_PERMITTED, 1, keep, CAP_SET) != 0 ||
        cap_set_flag(caps, CAP_EFFECTIVE, 1, keep, CAP_SET) != 0) {
        int saved = errno;       /* cap_free() may clobber errno */
        cap_free(caps);
        errno = saved;
        perror("libdrmtap-server: cap_set_flag failed"); return -1;
    }

    int ret = cap_set_proc(caps);
    int saved = errno;           /* preserve before cap_free() touches errno */
    cap_free(caps);

    if (ret != 0) {
        errno = saved;
        perror("libdrmtap-server: cap_set_proc failed");
        return -1;
    }
    fprintf(stderr, "libdrmtap-server: dropped caps, keeping CAP_SYS_ADMIN\n");
    return 0;
}
#endif

#ifdef HAVE_SECCOMP
// Install seccomp filter allowing only needed syscalls
static int install_seccomp(void) {
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL_PROCESS); // SCMP_ACT_LOG
    if (!ctx) {
        /* seccomp_init does not set errno; perror would print a stale value. */
        fprintf(stderr, "libdrmtap-server: seccomp_init failed\n"); return -1;
    }

    /* Same base set drmtap-helper.c uses, plus what the socket-server accept
     * loop needs that the ephemeral helper never does: accept4/poll/getsockopt
     * (serving the listen socket + SO_PEERCRED), futex (contended pthread_mutex
     * ops between this thread and drmtap_server_stop()'s caller thread), and
     * unlink/unlinkat (this thread's own socket-path cleanup after accept_loop
     * returns, still running under this filter). open/openat are deliberately
     * NOT allowed — the DRM device and listen socket are both already open
     * before this filter installs, and nothing after this point ever opens
     * another path. */
    int allowed[] = {
        SCMP_SYS(read), SCMP_SYS(write), SCMP_SYS(close),
        SCMP_SYS(sendto), SCMP_SYS(sendmsg), SCMP_SYS(recvfrom),
        SCMP_SYS(mmap), SCMP_SYS(munmap), SCMP_SYS(brk),
        SCMP_SYS(fstat), SCMP_SYS(newfstatat), SCMP_SYS(fcntl),
        SCMP_SYS(exit_group), SCMP_SYS(exit), SCMP_SYS(rt_sigreturn),
        SCMP_SYS(clock_gettime),
        SCMP_SYS(accept4), SCMP_SYS(poll), SCMP_SYS(getsockopt),
        SCMP_SYS(futex), SCMP_SYS(unlink), SCMP_SYS(unlinkat),
        SCMP_SYS(madvise), SCMP_SYS(rt_sigprocmask)
    };
    for (size_t i = 0; i < sizeof(allowed) / sizeof(allowed[0]); i++) {
        /* seccomp_rule_add returns -errno (it does not set errno itself). */
        int rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, allowed[i], 0);
        if (rc != 0) {
            seccomp_release(ctx);
            fprintf(stderr, "libdrmtap_server: seccomp_rule_add failed: %s\n",
                    strerror(-rc));
            return -1;
        }
    }

    /* ioctl: only the DRM ioctl type ('d', bits 8-15), same reasoning as the
     * helper — a memory-corrupted worker cannot reach an unrelated ioctl. */
    {
       int rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(ioctl), 1,
                                  SCMP_A1(SCMP_CMP_MASKED_EQ, 0xFF00u,
                                          (unsigned)'d' << 8));
        if (rc != 0) {
            seccomp_release(ctx);
            fprintf(stderr, "libdrmtap_server: seccomp ioctl rule failed: %s\n",
                    strerror(-rc));
            return -1;
        }
    }

    /* DMA_BUF_IOCTL_SYNC (type 'b') for cursor pixel-read cache coherence,
     * same as the helper's cursor path. */
    {
        int rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(ioctl), 1,
                                  SCMP_A1(SCMP_CMP_EQ,
                                          (scmp_datum_t)DMA_BUF_IOCTL_SYNC));
        if (rc != 0) {
            seccomp_release(ctx);
            fprintf(stderr,
                    "libdrmtap_server: seccomp dma-buf ioctl rule failed: %s\n",
                    strerror(-rc));
            return -1;
        }
    }

    int ret = seccomp_load(ctx);
    seccomp_release(ctx);

    if (ret != 0) {
        /* seccomp_load also returns -errno. */
        fprintf(stderr, "libdrmtap_server: seccomp_load failed: %s\n",
                strerror(-ret));
        return -1;
    }
    return 0;
}
#endif

struct drmtap_server {
    /* Owned and used exclusively by the worker thread from open to close. */
    drmtap_ctx *ctx;
    int listen_fd;
    int active_fd;            /* connection currently being served, or -1;
                                  guarded by `lock` so drmtap_server_stop()
                                  (caller thread) can shut it down to unblock
                                  a blocked recv on that fd */

    char socket_path[256];
    uid_t expected_uid;
    char device_path[256];
    int device_path_set;
    int debug;

    pthread_t thread;
    pthread_mutex_t lock;
    pthread_cond_t ready_cv;
    int ready;                 /* 1 once startup (open+bind+listen) finished */
    int start_ok;               /* result of that startup, valid once ready */
    volatile int stop;

    char error_msg[512];
};

/* Error string for a NULL srv (drmtap_server_start failure before/without a
 * live handle to return). Thread-local so concurrent failures on different
 * threads do not race on one buffer — mirrors g_static_error in drmtap.c. */
static _Thread_local char g_static_error[512] = "";

static void set_error(drmtap_server *srv, const char *fmt, ...) {
    va_list ap;
    char buf[512];
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    if (srv) {
        snprintf(srv->error_msg, sizeof(srv->error_msg), "%s", buf);
    }
    snprintf(g_static_error, sizeof(g_static_error), "%s", buf);
}

const char *drmtap_server_error(drmtap_server *srv) {
    if (srv) {
        return srv->error_msg[0] ? srv->error_msg : NULL;
    }
    return g_static_error[0] ? g_static_error : NULL;
}

/* ========================================================================= */
/* Socket setup                                                              */
/* ========================================================================= */

static int ensure_parent_dir(const char *path) {
    char buf[512];
    snprintf(buf, sizeof(buf), "%s", path);
    char *slash = strrchr(buf, '/');
    if (!slash || slash == buf) {
        return 0; /* no parent component, or parent is "/" */
    }
    *slash = '\0';
    if (buf[0] == '\0') {
        return 0;
    }
    struct stat st;
    if (stat(buf, &st) == 0) {
        return S_ISDIR(st.st_mode) ? 0 : -1;
    }
    if (mkdir(buf, 0755) == 0) {
        return 0;
    }
    return (errno == EEXIST) ? 0 : -1;
}

/* World-connectable (0666) on purpose: access control is enforced in code
 * (SO_PEERCRED vs expected_uid, see accept_loop) rather than via filesystem
 * ACLs. This sidesteps depending on fd-inheritance surviving an intermediary
 * like `sudo`, which is not guaranteed (modern sudo closes inherited fds by
 * default) — the consumer just connects to a well-known path instead. */
static int bind_listen_socket(drmtap_server *srv) {
    if (ensure_parent_dir(srv->socket_path) != 0) {
        set_error(srv, "could not create parent directory for %s: %s",
                  srv->socket_path, strerror(errno));
        return -1;
    }

    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        set_error(srv, "socket() failed: %s", strerror(errno));
        return -1;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    if (snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", srv->socket_path)
        >= (int)sizeof(addr.sun_path)) {
        set_error(srv, "socket path too long: %s", srv->socket_path);
        close(fd);
        return -1;
    }

    unlink(srv->socket_path); /* best effort: clear a stale node from a prior run */

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        set_error(srv, "bind(%s) failed: %s", srv->socket_path, strerror(errno));
        close(fd);
        return -1;
    }
    if (chmod(srv->socket_path, 0666) != 0) {
        set_error(srv, "chmod(%s) failed: %s", srv->socket_path, strerror(errno));
        close(fd);
        unlink(srv->socket_path);
        return -1;
    }
    /* Backlog of 1: exactly one intended consumer connects at a time; a second
     * simultaneous connect attempt queues briefly rather than being refused
     * outright, which is fine since the accept loop drains it promptly. */
    if (listen(fd, 1) != 0) {
        set_error(srv, "listen() failed: %s", strerror(errno));
        close(fd);
        unlink(srv->socket_path);
        return -1;
    }

    srv->listen_fd = fd;
    return 0;
}

/* ========================================================================= */
/* Per-connection command dispatch                                           */
/* ========================================================================= */

static void handle_grab(drmtap_server *srv, int fd) {
    drmtap_server_grab_reply_t reply;
    memset(&reply, 0, sizeof(reply));
    drmtap_frame_info frame;
    memset(&frame, 0, sizeof(frame));

    int gret = drmtap_grab_desc(srv->ctx, &reply.desc, &frame);
    int fd_to_send = -1;
    if (gret == 0) {
        reply.status = DRMTAP_SERVER_GRAB_OK;   
        fd_to_send = reply.desc.dma_buf_fd; /* may be -1: an import-once cache
                                                hit for an fb_id the consumer
                                                already imported needs no fd */
    } else {
        reply.status = DRMTAP_SERVER_GRAB_ERROR;
        if (srv->debug) {
            fprintf(stderr, "[drmtap_server] grab_desc failed (%d): %s\n",
                    gret, drmtap_error(srv->ctx) ? drmtap_error(srv->ctx) : "");
        }
    }

    int send_ret = wire_send_fd(fd, fd_to_send, &reply, sizeof(reply));
    if (gret == 0) {
        /* Release AFTER sending: sendmsg() has already dup'd the fd into the
         * kernel's socket-layer queue for the peer, so releasing our own copy
         * now is safe (same order examples/split_capture.c uses). */
        drmtap_frame_release(srv->ctx, &frame);
    }
    (void)send_ret; /* a failed send just ends the connection; caller detects
                        it on the next recv and returns */
}

static void handle_get_cursor(drmtap_server *srv, int fd) {
    drmtap_server_cursor_reply_t reply;
    memset(&reply, 0, sizeof(reply));
    drmtap_cursor_info cursor;
    memset(&cursor, 0, sizeof(cursor));

    int cret = drmtap_get_cursor(srv->ctx, &cursor);
    if (cret == 0) {
        reply.x = cursor.x;
        reply.y = cursor.y;
        reply.hot_x = cursor.hot_x;
        reply.hot_y = cursor.hot_y;
        reply.width = cursor.width;
        reply.height = cursor.height;
        reply.visible = cursor.visible ? 1u : 0u;
        reply.data_size = (cursor.visible && cursor.pixels)
                               ? cursor.width * cursor.height * 4u
                               : 0u;
    } else if (srv->debug) {
        fprintf(stderr, "[drmtap_server] get_cursor failed (%d): %s\n",
                cret, drmtap_error(srv->ctx) ? drmtap_error(srv->ctx) : "");
    }

    if (wire_send_fd(fd, -1, &reply, sizeof(reply)) == 0 && reply.data_size > 0) {
        wire_send_all(fd, cursor.pixels, reply.data_size);
    }
    drmtap_cursor_release(srv->ctx, &cursor);
}

/* Serve one connection until it disconnects, sends CMD_QUIT, or a framing
 * error occurs. Runs entirely on the worker thread. */
static void serve_connection(drmtap_server *srv, int fd) {
    for (;;) {
        helper_cmd_grab_t hcmd;
        if (wire_recv_all(fd, &hcmd, sizeof(hcmd)) != 0) {
            return; /* peer disconnected */
        }
        if (!wire_cmd_valid(&hcmd)) {
            return; /* fail closed on a malformed/mismatched-version frame */
        }
        switch (hcmd.type) {
            case CMD_GRAB:
                handle_grab(srv, fd);
                break;
            case CMD_GET_CURSOR:
                handle_get_cursor(srv, fd);
                break;
            case CMD_QUIT:
            default:
                return;
        }
    }
}

/* ========================================================================= */
/* Accept loop + worker thread                                               */
/* ========================================================================= */

static void accept_loop(drmtap_server *srv) {
    while (!srv->stop) {
        struct pollfd pfd = { .fd = srv->listen_fd, .events = POLLIN };
        int pr = poll(&pfd, 1, 500);
        if (pr < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (pr == 0 || srv->stop) {
            continue;
        }

        int fd = accept4(srv->listen_fd, NULL, NULL, SOCK_CLOEXEC);
        if (fd < 0) {
            continue; /* transient accept error; keep serving */
        }

        struct ucred cred;
        socklen_t clen = sizeof(cred);
        if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cred, &clen) != 0 ||
            clen != sizeof(cred) || cred.uid != srv->expected_uid) {
            if (srv->debug) {
                fprintf(stderr, "[drmtap_server] rejecting connection "
                                 "(peer credential check failed)\n");
            }
            close(fd);
            continue;
        }

        pthread_mutex_lock(&srv->lock);
        srv->active_fd = fd;
        pthread_mutex_unlock(&srv->lock);

        serve_connection(srv, fd);

        pthread_mutex_lock(&srv->lock);
        srv->active_fd = -1;
        pthread_mutex_unlock(&srv->lock);
        close(fd);
    }
}

static void report_startup_result(drmtap_server *srv, int ok) {
    pthread_mutex_lock(&srv->lock);
    srv->start_ok = ok;
    srv->ready = 1;
    pthread_cond_signal(&srv->ready_cv);
    pthread_mutex_unlock(&srv->lock);
}

static void *worker_main(void *arg) {
    drmtap_server *srv = (drmtap_server *)arg;

    // supress openat syscall from malloc
    mallopt(M_MMAP_THRESHOLD, -1);
    mallopt(M_TRIM_THRESHOLD, -1);

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        set_error(srv, "prctl(PR_SET_NO_NEW_PRIVS) failed: %s", strerror(errno));
        report_startup_result(srv, 0);
        goto cleanup;
    }

    drmtap_config dcfg;
    memset(&dcfg, 0, sizeof(dcfg));
    dcfg.device_path = srv->device_path_set ? srv->device_path : NULL;
    dcfg.debug = srv->debug;

    srv->ctx = drmtap_open(&dcfg);
    if (!srv->ctx) {
        set_error(srv, "drmtap_open failed: %s",
                  drmtap_error(NULL) ? drmtap_error(NULL) : "(unknown)");
        report_startup_result(srv, 0);
        goto cleanup;
    }

    if (bind_listen_socket(srv) != 0) {
        report_startup_result(srv, 0);
        goto cleanup;
    }

#ifdef HAVE_LIBCAP
    (void)strerror(EINVAL); // cache glibc strerror to prevent lazy loading with openat()
    if (drop_caps() != 0) {
        set_error(srv, "could not drop capabilities");
        report_startup_result(srv, 0);
        goto cleanup;
    }
#endif
#ifdef HAVE_SECCOMP
    if (install_seccomp() != 0) {
        set_error(srv, "could not install seccomp filter");
        report_startup_result(srv, 0);
        goto cleanup;
    }
#endif

    report_startup_result(srv, 1);

    accept_loop(srv);

cleanup:
    if (srv->listen_fd >= 0) {
        close(srv->listen_fd);
        srv->listen_fd = -1;
    }
    if (srv->socket_path[0]) {
        unlink(srv->socket_path);
    }
    if (srv->ctx) {
        drmtap_close(srv->ctx);
        srv->ctx = NULL;
    }
    return NULL;
}

/* ========================================================================= */
/* Public API                                                                */
/* ========================================================================= */

drmtap_server *drmtap_server_start(const drmtap_server_config *cfg) {
    if (!cfg || !cfg->socket_path || !cfg->socket_path[0]) {
        snprintf(g_static_error, sizeof(g_static_error),
                 "drmtap_server_start: socket_path is required");
        return NULL;
    }

    drmtap_server *srv = calloc(1, sizeof(*srv));
    if (!srv) {
        snprintf(g_static_error, sizeof(g_static_error),
                 "drmtap_server_start: out of memory");
        return NULL;
    }
    srv->listen_fd = -1;
    srv->active_fd = -1;
    srv->expected_uid = cfg->expected_uid;
    srv->debug = cfg->debug;
    snprintf(srv->socket_path, sizeof(srv->socket_path), "%s", cfg->socket_path);
    if (cfg->device_path && cfg->device_path[0]) {
        snprintf(srv->device_path, sizeof(srv->device_path), "%s", cfg->device_path);
        srv->device_path_set = 1;
    }

    pthread_mutex_init(&srv->lock, NULL);
    pthread_cond_init(&srv->ready_cv, NULL);

    if (pthread_create(&srv->thread, NULL, worker_main, srv) != 0) {
        snprintf(g_static_error, sizeof(g_static_error),
                 "drmtap_server_start: pthread_create failed: %s", strerror(errno));
        pthread_mutex_destroy(&srv->lock);
        pthread_cond_destroy(&srv->ready_cv);
        free(srv);
        return NULL;
    }

    pthread_mutex_lock(&srv->lock);
    while (!srv->ready) {
        pthread_cond_wait(&srv->ready_cv, &srv->lock);
    }
    int ok = srv->start_ok;
    pthread_mutex_unlock(&srv->lock);

    if (!ok) {
        /* worker_main already returned (it only signals ready after either
         * failing or fully starting the accept loop) — safe to join. */
        pthread_join(srv->thread, NULL);
        snprintf(g_static_error, sizeof(g_static_error), "%s", srv->error_msg);
        pthread_mutex_destroy(&srv->lock);
        pthread_cond_destroy(&srv->ready_cv);
        free(srv);
        return NULL;
    }

    return srv;
}

void drmtap_server_stop(drmtap_server *srv) {
    if (!srv) {
        return;
    }
    srv->stop = 1;
    pthread_mutex_lock(&srv->lock);
    if (srv->active_fd >= 0) {
        /* Unblocks a recv the worker thread may be inside right now, mid
         * connection, so stop() does not have to wait out a stalled peer. */
        shutdown(srv->active_fd, SHUT_RDWR);
    }
    pthread_mutex_unlock(&srv->lock);

    pthread_join(srv->thread, NULL);
    pthread_mutex_destroy(&srv->lock);
    pthread_cond_destroy(&srv->ready_cv);
    free(srv);
}
