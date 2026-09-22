// Every .c and .h file MUST start with this header block:

/*
 * libdrmtap — DRM/KMS screen capture library for Linux
 * https://github.com/fxd0h/libdrmtap
 *
 * Copyright (c) 2026 Mariano Abad <weimaraner@gmail.com>
 * SPDX-License-Identifier: MIT
 */

/**
 * @file screenshot_server.c
 * @brief Example — capture one frame and write PPM to stdout from socket opened by priveleged libdrmtap_server
 * Usage:
 *   screenshot_server > image.ppm
 */

#define _GNU_SOURCE
#include "server_wire.h"
#include "wire.h"

#include <stdlib.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include "drmtap.h"

int main(int argc, char *argv[]) {
    (void)argc;
    (void)argv;
    const char *socket_path = "/run/drmtap_server_example/server.sock";
    const char *device_path = NULL;
    int result = 0;
    drmtap_ctx* ctx = NULL;
    drmtap_frame_info frame;
    memset(&frame, 0, sizeof(frame));

    int sock = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (sock < 0) {
        fprintf(stderr, "Failed to open: %s\n", strerror(errno));
        return -1;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", socket_path);
    if (connect(sock, (struct sockaddr*)(&addr), sizeof(addr)) != 0) {
        fprintf(stderr, "connect(%s) failed: %s", socket_path, strerror(errno));
        result = -1;
        goto cleanup;
    }

    struct ucred cred;
    socklen_t clen = sizeof(cred);
    if (getsockopt(sock, SOL_SOCKET, SO_PEERCRED, &cred, &clen) != 0 || clen != sizeof(cred) || cred.uid != 0) {
        fprintf(stderr, "refusing non-root drmtap_server at %s", socket_path);
        result = -1;
        goto cleanup;
    }

    ctx = drmtap_open_render(device_path);
    if (!ctx) {
        fprintf(stderr, "drmtap_open_render failed: %s", drmtap_error(NULL));
        result = -1;
        goto cleanup;
    }

    // list displays and pick the first one
    uint32_t chosen_id = 0;
    {
        helper_cmd_grab_t lcmd = wire_cmd(CMD_LIST_DISPLAYS, 0);
        if (wire_send_all(sock, &lcmd, sizeof(lcmd)) != 0) {
            fprintf(stderr, "send CMD_LIST_DISPLAYS failed: %s", strerror(errno));
            result = -1;
            goto cleanup;
        }

        drmtap_server_list_reply_t hdr;
        memset(&hdr, 0, sizeof(hdr));
        if (wire_recv_all(sock, &hdr, sizeof(hdr)) != 0 || hdr.count == 0) {
            fprintf(stderr, "recv CMD_LIST_DISPLAYS reply failed or no displays\n");
            result = -1;
            goto cleanup;
        }

        int got_first = 0;
        for (uint32_t i = 0; i < hdr.count; i++) {
            drmtap_server_display_t d;
            memset(&d, 0, sizeof(d));
            if (wire_recv_all(sock, &d, sizeof(d)) != 0) {
                fprintf(stderr, "recv display entry failed\n");
                result = -1;
                goto cleanup;
            }
            fprintf(stderr, "display [%u] %s: %ux%u@%uHz at (%d,%d)\n",
                    d.id, d.name, d.width, d.height, d.refresh_hz, d.x, d.y);
            if (!got_first) {
                chosen_id = d.id;
                got_first = 1;
            }
        }
    }

    // grab screen and save as image.ppm
    {
        // send request
        helper_cmd_grab_t hcmd = wire_cmd(CMD_GRAB, 0);
        hcmd.crtc_id = chosen_id; /* reused as display id for this protocol, not a real crtc id */
        if (wire_send_all(sock, &hcmd, sizeof(hcmd)) != 0) {
            fprintf(stderr, "send CMD_GRAB failed: %s", strerror(errno));
            result = -1;
            goto cleanup;
        }

        // wait reply
        drmtap_server_grab_reply_t reply;
        memset(&reply, 0, sizeof(reply));
        int fd = -1; // target fd
        if (wire_recv_fd(sock, &reply, sizeof(reply), &fd)) {
            fprintf(stderr, "recv grab reply failed: %s", strerror(errno));
            result = -1;
            goto cleanup;
        }
        if (reply.status != DRMTAP_SERVER_GRAB_OK) {
            if (fd >= 0)
                close(fd);
            fprintf(stderr, "drmtap_server reported a grab error");
            result = -1;
            goto cleanup;
        }

        reply.desc.dma_buf_fd = fd;

        // convert dmabuf
        int cret = drmtap_convert_dmabuf(ctx, &reply.desc, &frame);
        if (fd >= 0)
            close(fd);
        if (cret != 0 || !frame.data) {
            fprintf(stderr, "drmtap_convert_dmabuf failed (%d): %s", cret, drmtap_error(ctx));
            result = -1;
            goto cleanup;
        }

        /* Write PPM P6 header */
        fprintf(stdout, "P6\n%u %u\n255\n", frame.width, frame.height);

        /* Convert XRGB8888/ARGB8888 → RGB and write row by row
        *
        * XRGB8888 layout in memory (little-endian):
        *   byte[0] = B, byte[1] = G, byte[2] = R, byte[3] = X/A
        *
        * PPM P6 needs: R, G, B per pixel
        */
        uint8_t *rgb_row = malloc(frame.width * 3);
        if (!rgb_row) {
            fprintf(stderr, "malloc failed\n");
            result = -1;
            goto cleanup;
        }

        const uint8_t *src = (const uint8_t *)frame.data;
        for (uint32_t y = 0; y < frame.height; y++) {
            const uint8_t *row = src + y * frame.stride;
            for (uint32_t x = 0; x < frame.width; x++) {
                /* XRGB8888 little-endian: B G R X */
                rgb_row[x * 3 + 0] = row[x * 4 + 2];  /* R */
                rgb_row[x * 3 + 1] = row[x * 4 + 1];  /* G */
                rgb_row[x * 3 + 2] = row[x * 4 + 0];  /* B */
            }
            fwrite(rgb_row, 1, frame.width * 3, stdout);
        }

        free(rgb_row);

        fprintf(stderr, "Wrote %ux%u PPM (%u bytes pixel data)\n",
                frame.width, frame.height, frame.stride * frame.height);
    }

    // get cursor data and print to stderr just for test
    {
        // send request
        helper_cmd_grab_t hcmd = wire_cmd(CMD_GET_CURSOR, 0);
        hcmd.crtc_id = chosen_id;
        if (wire_send_all(sock, &hcmd, sizeof(hcmd)) != 0) {
            fprintf(stderr, "send CMD_GET_CURSOR failed: %s", strerror(errno));
            result = -1;
            goto cleanup;
        }

        // wait reply
        drmtap_server_cursor_reply_t reply;
        memset(&reply, 0, sizeof(reply));
        if (wire_recv_all(sock, &reply, sizeof(reply))) {
            fprintf(stderr, "recv grab reply failed: %s", strerror(errno));
            result = -1;
            goto cleanup;
        }
        if (reply.data_size > 0) {
            uint8_t *cursor_pixels = malloc(reply.data_size);
            if (cursor_pixels && wire_recv_all(sock, cursor_pixels, reply.data_size) == 0) {
                /* cursor_pixels now holds ARGB8888 premultiplied, width*height*4 bytes */
            }
            free(cursor_pixels);
        }
        fprintf(stderr, "cursor pos x: %d, y: %d\n", reply.x, reply.y);
        fprintf(stderr, "rect x: %d, y: %d\n", reply.width, reply.height);
        fprintf(stderr, "cursor visible %d\n", reply.visible);
    }
cleanup:
    if (ctx) {
        drmtap_close(ctx);
    }
    ctx = NULL;
    close(sock);

    return result;
}