/*
 * Copyright (c) 2016-2017, Linaro Ltd.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its contributors
 * may be used to endorse or promote products derived from this software without
 * specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
#include <assert.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "qdl.h"

struct sahara_pkt {
    uint32_t cmd;
    uint32_t length;

    union {
        struct {
            uint32_t version;
            uint32_t compatible;
            uint32_t max_len;
            uint32_t mode;
        } hello_req;
        struct {
            uint32_t version;
            uint32_t compatible;
            uint32_t status;
            uint32_t mode;
        } hello_resp;
        struct {
            uint32_t image;
            uint32_t offset;
            uint32_t length;
        } read_req;
        struct {
            uint32_t image;
            uint32_t status;
        } eoi;
        //struct {
        //} done_req;
        struct {
            uint32_t status;
        } done_resp;
        struct {
            uint64_t image;
            uint64_t offset;
            uint64_t length;
        } read64_req;
        struct {
            uint32_t cmd;
        } cmd_req;
        struct {
            uint32_t cmd;
            uint32_t data_len;
        } cmd_resp;
    };
};

static void sahara_send_reset(struct qdl_device *ctx) {
    struct sahara_pkt resp;

    memset(&resp, 0, sizeof(struct sahara_pkt));
    resp.cmd = 7;
    resp.length = 8;

    qdl_write(ctx, &resp, resp.length);
}

static void sahara_hello(struct qdl_device *ctx, struct sahara_pkt *pkt, uint32_t mode) {
    struct sahara_pkt resp;

    assert(pkt->length == 0x30);

    printf("HELLO version: 0x%x compatible: 0x%x max_len: %d mode: %d\n",
           pkt->hello_req.version, pkt->hello_req.compatible, pkt->hello_req.max_len, pkt->hello_req.mode);

    memset(&resp, 0, sizeof(struct sahara_pkt));
    resp.cmd = 2;
    resp.length = 0x30;
    resp.hello_resp.version = 2;
    resp.hello_resp.compatible = 1;
    resp.hello_resp.mode = mode;

    qdl_write(ctx, &resp, resp.length);
}

static int sahara_read_common(struct qdl_device *ctx, int prog_fd, off_t offset, size_t len) {
    ssize_t n;
    void *buf;
    int ret = 0;


    buf = malloc(len);
    if (!buf)
        return -ENOMEM;

    lseek(prog_fd, offset, SEEK_SET);
    n = read(prog_fd, buf, len);
    if (n != len) {
        ret = -errno;
        goto out;
    }

    n = qdl_write(ctx, buf, n);
    if (n != len)
        err(1, "failed to write %zu bytes to sahara", len);

    free(buf);

    out:
    return ret;
}

static void sahara_read(struct qdl_device *ctx, struct sahara_pkt *pkt, char *img_arr[], bool single_image) {
    unsigned int image;
    int ret;
    int fd;

    assert(pkt->length == 0x14);

    printf("READ image: %d offset: 0x%x length: 0x%x\n",
           pkt->read_req.image, pkt->read_req.offset, pkt->read_req.length);

    if (single_image)
        image = 0;
    else
        image = pkt->read_req.image;

    if (image >= MAPPING_SZ || !img_arr[image]) {
        fprintf(stderr, "Device specified invalid image: %u\n", image);
        sahara_send_reset(ctx);
        return;
    }

    fd = open(img_arr[image], O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "Can not open %s: %s\n", img_arr[image], strerror(errno));
        // Maybe this read was optional.  Notify device of error and let
        // it decide how to proceed.
        sahara_send_reset(ctx);
        return;
    }

    ret = sahara_read_common(ctx, fd, pkt->read_req.offset, pkt->read_req.length);
    if (ret < 0)
        errx(1, "failed to read image chunk to sahara");

    close(fd);
}

static void sahara_read64(struct qdl_device *ctx, struct sahara_pkt *pkt, char *img_arr[], bool single_image) {
    unsigned int image;
    int ret;
    int fd;

    assert(pkt->length == 0x20);

    printf("READ64 image: %" PRId64 " offset: 0x%" PRIx64 " length: 0x%" PRIx64 "\n",
           pkt->read64_req.image, pkt->read64_req.offset, pkt->read64_req.length);

    if (single_image)
        image = 0;
    else
        image = pkt->read64_req.image;

    if (image >= MAPPING_SZ || !img_arr[image]) {
        fprintf(stderr, "Device specified invalid image: %u\n", image);
        sahara_send_reset(ctx);
        return;
    }
    fd = open(img_arr[image], O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "Can not open %s: %s\n", img_arr[image], strerror(errno));
        // Maybe this read was optional.  Notify device of error and let
        // it decide how to proceed.
        sahara_send_reset(ctx);
        return;
    }

    ret = sahara_read_common(ctx, fd, (off_t) pkt->read64_req.offset, pkt->read64_req.length);
    if (ret < 0)
        errx(1, "failed to read image chunk to sahara");

    close(fd);
}

static void sahara_eoi(struct qdl_device *ctx, struct sahara_pkt *pkt) {
    struct sahara_pkt done;

    assert(pkt->length == 0x10);

    printf("END OF IMAGE image: %d status: %d\n", pkt->eoi.image, pkt->eoi.status);

    if (pkt->eoi.status != 0) {
        printf("received non-successful result\n");
        return;
    }

    done.cmd = 5;
    done.length = 0x8;
    qdl_write(ctx, &done, done.length);
}

static void sahara_exe_cmd(struct qdl_device *ctx, struct sahara_pkt *pkt, uint32_t cmd) {
    struct sahara_pkt resp;
    uint8_t buf[256];
    int n;
    uint32_t len;

    memset(&resp, 0, sizeof(struct sahara_pkt));
    resp.cmd = 0xd;
    resp.length = 12;
    resp.cmd_req.cmd = cmd;
    qdl_write(ctx, &resp, resp.length);

    n = qdl_read(ctx, pkt, sizeof(struct sahara_pkt), 1000);
    if (n < 0) {
        printf("read failed\n");
        return;
    }

    len = pkt->cmd_resp.data_len;
    printf("exe cmd %d Response: data_len=%d\n", pkt->cmd_resp.cmd, len);

    memset(&resp, 0, sizeof(struct sahara_pkt));
    resp.cmd = 0xf;
    resp.length = 12;
    resp.cmd_req.cmd = pkt->cmd_resp.cmd;
    qdl_write(ctx, &resp, resp.length);

    n = qdl_read(ctx, buf, len, 1000);
    if (n < 0) {
        printf("sahara_exe_cmd: read failed\n");
        return;
    }
    assert(n == len);

    switch (resp.cmd_req.cmd) {
        case 0x01:
            ctx->serial = buf[3] << 24 | buf[2] << 16 | buf[1] << 8 | buf[0];
            printf("serial: 0x%08X\n", ctx->serial);
            break;
        case 0x02:
            ctx->msm_id_len = len;
            ctx->msm_id = malloc(len);
            memcpy(ctx->msm_id, buf, len);
            print_hex_dump("msm-id", ctx->msm_id, len);
            break;
        case 0x03:
            ctx->pk_hash_len = len;
            ctx->pk_hash = malloc(len);
            memcpy(ctx->pk_hash, buf, len);
            print_hex_dump("pk_hash", ctx->pk_hash, len);
            break;
    }
}

static void sahara_switch_mode(struct qdl_device *ctx, uint32_t mode) {
    struct sahara_pkt resp;

    memset(&resp, 0, sizeof(struct sahara_pkt));
    resp.cmd = 0xc;
    resp.length = 12;
    resp.cmd_req.cmd = mode;
    qdl_write(ctx, &resp, resp.length);
}

static int sahara_done(struct qdl_device *ctx, struct sahara_pkt *pkt) {
    (void) ctx;
    assert(pkt->length == 0xc);

    printf("DONE status: %d\n", pkt->done_resp.status);

    // 0 == PENDING, 1 == COMPLETE.  Device expects more images if
    // PENDING is set in status.
    return (int) pkt->done_resp.status;
}

int sahara_run(struct qdl_device *ctx, char *img_arr[], bool single_image) {
    struct sahara_pkt *pkt;
    char buf[4096];
    char tmp[32];
    bool done = false;
    bool cmd_mode = true;
    int n;

    while (!done) {
        n = qdl_read(ctx, buf, sizeof(buf), 1000);
        if (n < 0)
            break;

        pkt = (struct sahara_pkt *) buf;
        if (n != pkt->length) {
            fprintf(stderr, "length not matching\n");
            print_hex_dump("cmd_response", buf, n);
            return -EINVAL;
        }

        switch (pkt->cmd) {
            case 1:
                if (cmd_mode) sahara_hello(ctx, pkt, 3);
                else sahara_hello(ctx, pkt, 0);
                break;
            case 3:
                sahara_read(ctx, pkt, img_arr, single_image);
                break;
            case 4:
                sahara_eoi(ctx, pkt);
                break;
            case 6:
                done = sahara_done(ctx, pkt);

                /* E.g MSM8916 EDL reports done = 0 here */
                if (single_image)
                    done = true;
                break;
            case 0xb:
                if (cmd_mode) {
                    sahara_exe_cmd(ctx, pkt, 1);
                    sahara_exe_cmd(ctx, pkt, 2);
                    sahara_exe_cmd(ctx, pkt, 3);
                    sahara_switch_mode(ctx, 0);
                    cmd_mode = false;
                }
                break;
            case 0x12:
                sahara_read64(ctx, pkt, img_arr, single_image);
                break;
            default:
                sprintf(tmp, "CMD%x", pkt->cmd);
                print_hex_dump(tmp, buf, n);
                break;
        }
    }

    return done ? 0 : -1;
}
