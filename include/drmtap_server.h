/*
 * libdrmtap — DRM/KMS screen capture library for Linux
 * https://github.com/fxd0h/libdrmtap
 *
 * Copyright (c) 2026 Mariano Abad <weimaraner@gmail.com>
 * SPDX-License-Identifier: MIT
 */

/**
 * @file drmtap_server.h
 * @brief Public API for libdrmtap_servers
 */

#ifndef DRMTAP_SERVER_H
#define DRMTAP_SERVER_H

#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct drmtap_server drmtap_server;

typedef struct {
    const char *socket_path;
    uid_t expected_uid;
    const char *device_path;
    int debug;
} drmtap_server_config;

drmtap_server *drmtap_server_start(const drmtap_server_config *cfg);

void drmtap_server_stop(drmtap_server *srv);

const char *drmtap_server_error(drmtap_server *srv);

#ifdef __cplusplus
}
#endif

#endif /* DRMTAP_SERVER_H */