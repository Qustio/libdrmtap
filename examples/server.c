/*
 * libdrmtap — DRM/KMS screen capture library for Linux
 * https://github.com/fxd0h/libdrmtap
 *
 * Copyright (c) 2026 Mariano Abad <weimaraner@gmail.com>
 * SPDX-License-Identifier: MIT
 */

/**
 * @file server.c
 * @brief Root-run stand-in for the socket integration.
 *
 * Usage:
 *   sudo ./server --uid $(id -u <consumer-user>) \
 *       [--socket /run/drmtap_server_example/server.sock]
 *       [--device /dev/dri/card0] [--debug]
 */

#include "drmtap_server.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>

static volatile sig_atomic_t g_stop = 0;

static void on_signal(int sig) {
    (void)sig;
    g_stop = 1;
}

int main(int argc, char **argv) {
    const char *socket_path = "/run/drmtap_server_example/server.sock";
    const char *device_path = NULL;
    uid_t expected_uid = 0;
    int have_uid = 0;
    int debug = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--uid") == 0 && i + 1 < argc) {
            expected_uid = (uid_t)strtoul(argv[++i], NULL, 10);
            have_uid = 1;
        } else if (strcmp(argv[i], "--socket") == 0 && i + 1 < argc) {
            socket_path = argv[++i];
        } else if (strcmp(argv[i], "--device") == 0 && i + 1 < argc) {
            device_path = argv[++i];
        } else if (strcmp(argv[i], "--debug") == 0) {
            debug = 1;
        } else {
            fprintf(stderr,
                    "usage: %s --uid <n> [--socket <path>] [--device <path>] [--debug]\n",
                    argv[0]);
            return 2;
        }
    }

    if (!have_uid) {
        fprintf(stderr, "server: --uid <n> is required "
                         "(the uid the consumer process runs as)\n");
        return 2;
    }

    drmtap_server_config cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.socket_path = socket_path;
    cfg.expected_uid = expected_uid;
    cfg.device_path = device_path;
    cfg.debug = debug;

    drmtap_server *srv = drmtap_server_start(&cfg);
    if (!srv) {
        fprintf(stderr, "server: failed to start: %s\n",
                drmtap_server_error(NULL) ? drmtap_server_error(NULL) : "(unknown)");
        return 1;
    }

    fprintf(stderr,
            "server: listening on %s, accepting uid=%u only "
            "(Ctrl-C to stop)\n",
            socket_path, (unsigned)expected_uid);

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);
    while (!g_stop) {
        pause();
    }

    fprintf(stderr, "server: stopping...\n");
    drmtap_server_stop(srv);
    fprintf(stderr, "server: stopped\n");
    return 0;
}
