/*
 * libdrmtap — DRM/KMS screen capture library for Linux
 * https://github.com/fxd0h/libdrmtap
 *
 * Copyright (c) 2026 Mariano Abad <weimaraner@gmail.com>
 * SPDX-License-Identifier: MIT
 */


/**
 * @file server_wire.h
 * @brief drmtap_server_wire.h — reply framing for the drmtap_server protocol.
 *
 * Shared by server.c (the producer) and any consumer. 
 * Header-only, no link dependency, mirrors how ../src/wire.h is shared
 * between drmtap-helper.c and the library.
 *
 * Command framing (CMD_GRAB / CMD_GET_CURSOR / CMD_QUIT, helper_cmd_grab_t,
 * wire_cmd/wire_cmd_valid) and the raw send/recv/SCM_RIGHTS primitives come
 * from ../src/wire.h — this header only adds the two reply payloads specific
 * to this protocol: the grab result (wraps the public drmtap_dmabuf_desc)
 * and the cursor result (drmtap_cursor_info has no flat wire-safe shape of
 * its own, so this mirrors helper_cursor_wire_t's proven layout).
 *
 * Both replies are sent via wire_send_fd()/received via wire_recv_fd() (a
 * cursor reply passes no fd; wire_send_fd/wire_recv_fd handle fd == -1
 * cleanly either way — see wire.h). A grab reply's dma_buf_fd field is
 * meaningless on the wire (it names an fd in the SENDER's process); the
 * receiver must overwrite it with whatever fd actually arrived via
 * SCM_RIGHTS (or -1 if status != OK, or the desc's own dma_buf_fd was -1 to
 * begin with) before passing the descriptor to drmtap_convert_dmabuf().
 */
#ifndef DRMTAP_SERVER_WIRE_H
#define DRMTAP_SERVER_WIRE_H

#include <stdint.h>
#include "drmtap.h"

#define DRMTAP_SERVER_GRAB_OK    0x00u
#define DRMTAP_SERVER_GRAB_ERROR 0x01u

typedef struct {
    uint8_t  status;         /* DRMTAP_SERVER_GRAB_* */
    uint8_t  _pad[7];        /* keep `desc` 8-byte aligned on the wire */
    drmtap_dmabuf_desc desc; /* valid only when status == OK */
} drmtap_server_grab_reply_t;

typedef struct {
    int32_t  x, y;
    int32_t  hot_x, hot_y;
    uint32_t width, height;
    uint32_t visible;
    uint32_t data_size;      /* width*height*4 if visible, else 0; raw ARGB8888
                                 premultiplied pixels follow immediately after
                                 this struct on the wire when data_size > 0 */
} drmtap_server_cursor_reply_t;

#endif /* DRMTAP_SERVER_WIRE_H */
