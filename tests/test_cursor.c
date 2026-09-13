/*
 * libdrmtap — DRM/KMS screen capture library for Linux
 * https://github.com/fxd0h/libdrmtap
 *
 * Copyright (c) 2026 Mariano Abad <weimaraner@gmail.com>
 * SPDX-License-Identifier: MIT
 */

/**
 * @file test_cursor.c
 * @brief Unit test — cursor helper-fallback classification (issue #58)
 *
 * No hardware needed. The direct cursor read reaches the privileged helper from
 * two places; both used to fire on any failure while claiming a privilege reason.
 * drmtap_cursor_needs_helper is the pure decision they now share: fork the helper
 * only for a genuine privilege failure, and treat a shape-change race or a
 * resource limit as a transient the next poll clears.
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include "drmtap.h"
#include "drmtap_internal.h"

#define TEST_ASSERT(cond) do { \
    if (!(cond)) { \
        fprintf(stderr, "FAIL: %s:%d: %s\n", __FILE__, __LINE__, #cond); \
        exit(1); \
    } \
} while (0)

/* GETFB2 returned NULL: the errno decides. */
static void test_getfb2_null_privilege_vs_race(void) {
    /* The kernel refused the fb read for lack of privilege — the helper's job. */
    TEST_ASSERT(drmtap_cursor_needs_helper(0, EACCES, 0) == 1);
    TEST_ASSERT(drmtap_cursor_needs_helper(0, EPERM, 0) == 1);
    /* Any other errno is a retired fb_id (a cursor shape-change race) or another
     * transient: the helper cannot fix it, and the next poll clears it. */
    TEST_ASSERT(drmtap_cursor_needs_helper(0, ENOENT, 0) == 0);
    TEST_ASSERT(drmtap_cursor_needs_helper(0, EINVAL, 0) == 0);
    TEST_ASSERT(drmtap_cursor_needs_helper(0, EAGAIN, 0) == 0);
    TEST_ASSERT(drmtap_cursor_needs_helper(0, 0, 0) == 0);
}

/* GETFB2 succeeded: the presence of a GEM handle decides. */
static void test_getfb2_ok_handle_decides(void) {
    /* No handle from a successful GETFB2 is the unprivileged result — the helper
     * can read what we cannot. */
    TEST_ASSERT(drmtap_cursor_needs_helper(1, 0, 0) == 1);
    /* Had a handle but produced no pixels (prime export, mmap, the size cap, or
     * the alloc failed): transient or a resource limit, not a privilege problem. */
    TEST_ASSERT(drmtap_cursor_needs_helper(1, 0, 1) == 0);
    /* errno is meaningless once GETFB2 succeeded: a stale EACCES must not drag the
     * read that HAD a handle into a needless fork of the helper. */
    TEST_ASSERT(drmtap_cursor_needs_helper(1, EACCES, 1) == 0);
    TEST_ASSERT(drmtap_cursor_needs_helper(1, EPERM, 1) == 0);
}

int main(void) {
    test_getfb2_null_privilege_vs_race();
    test_getfb2_ok_handle_decides();
    printf("test_cursor: all passed\n");
    return 0;
}
