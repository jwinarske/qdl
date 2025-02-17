/*
 * Copyright (c) 2016-2017, Linaro Ltd.
 * Copyright (c) 2018, The Linux Foundation. All rights reserved.
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
#include <linux/usbdevice_fs.h>
#include <linux/usb/ch9.h>
#include <sys/ioctl.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <libudev.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <sys/select.h>

#include "qdl.h"
#include "patch.h"
#include "ufs.h"

enum {
    QDL_FILE_UNKNOWN,
    QDL_FILE_PATCH,
    QDL_FILE_PROGRAM,
    QDL_FILE_UFS,
    QDL_FILE_CONTENTS,
};

bool qdl_debug;
static struct qdl_device qdl;

static int detect_type(const char *xml_file) {
    xmlNode *root;
    xmlDoc *doc;
    xmlNode *node;
    int type = QDL_FILE_UNKNOWN;

    doc = xmlReadFile(xml_file, NULL, 0);
    if (!doc) {
        fprintf(stderr, "[PATCH] failed to parse %s\n", xml_file);
        return -EINVAL;
    }

    root = xmlDocGetRootElement(doc);
    if (!xmlStrcmp(root->name, (xmlChar *) "patches")) {
        type = QDL_FILE_PATCH;
    } else if (!xmlStrcmp(root->name, (xmlChar *) "data")) {
        for (node = root->children; node; node = node->next) {
            if (node->type != XML_ELEMENT_NODE)
                continue;
            if (!xmlStrcmp(node->name, (xmlChar *) "program")) {
                type = QDL_FILE_PROGRAM;
                break;
            }
            if (!xmlStrcmp(node->name, (xmlChar *) "ufs")) {
                type = QDL_FILE_UFS;
                break;
            }
        }
    } else if (!xmlStrcmp(root->name, (xmlChar *) "contents")) {
        type = QDL_FILE_CONTENTS;
    }

    xmlFreeDoc(doc);

    return type;
}

static int parse_usb_desc(int fd, struct qdl_device *ctx, int *intf) {
    const struct usb_interface_descriptor *ifc;
    const struct usb_endpoint_descriptor *ept;
    const struct usb_device_descriptor *dev;
    const struct usb_config_descriptor *cfg;
    const struct usb_descriptor_header *hdr;
    unsigned type;
    int out;
    int in;
    unsigned k;
    unsigned l;
    ssize_t n;
    size_t out_size;
    size_t in_size;
    void *ptr;
    void *end;
    char desc[1024];

    n = read(fd, desc, sizeof(desc));
    if (n < 0)
        return (int) n;

    ptr = (void *) desc;
    end = ptr + n;

    dev = ptr;

    /* Consider only devices with vid 0x0506 and product id 0x9008 */
    if (dev->idVendor != 0x05c6 || dev->idProduct != 0x9008)
        return -EINVAL;

    ptr += dev->bLength;
    if (ptr >= end || dev->bDescriptorType != USB_DT_DEVICE)
        return -EINVAL;

    cfg = ptr;
    ptr += cfg->bLength;
    if (ptr >= end || cfg->bDescriptorType != USB_DT_CONFIG)
        return -EINVAL;

    for (k = 0; k < cfg->bNumInterfaces; k++) {
        if (ptr >= end)
            return -EINVAL;

        do {
            ifc = ptr;
            if (ifc->bLength < USB_DT_INTERFACE_SIZE)
                return -EINVAL;

            ptr += ifc->bLength;
        } while (ptr < end && ifc->bDescriptorType != USB_DT_INTERFACE);

        in = -1;
        out = -1;
        in_size = 0;
        out_size = 0;

        for (l = 0; l < ifc->bNumEndpoints; l++) {
            if (ptr >= end)
                return -EINVAL;

            do {
                ept = ptr;
                if (ept->bLength < USB_DT_ENDPOINT_SIZE)
                    return -EINVAL;

                ptr += ept->bLength;
            } while (ptr < end && ept->bDescriptorType != USB_DT_ENDPOINT);

            type = ept->bmAttributes & USB_ENDPOINT_XFERTYPE_MASK;
            if (type != USB_ENDPOINT_XFER_BULK)
                continue;

            if (ept->bEndpointAddress & USB_DIR_IN) {
                in = ept->bEndpointAddress;
                in_size = ept->wMaxPacketSize;
            } else {
                out = ept->bEndpointAddress;
                out_size = ept->wMaxPacketSize;
            }

            if (ptr >= end)
                break;

            hdr = ptr;
            if (hdr->bDescriptorType == USB_DT_SS_ENDPOINT_COMP)
                ptr += USB_DT_SS_EP_COMP_SIZE;
        }

        if (ifc->bInterfaceClass != 0xff)
            continue;

        if (ifc->bInterfaceSubClass != 0xff)
            continue;

        /* bInterfaceProtocol of 0xff, 0x10 and 0x11 has been seen */
        if (ifc->bInterfaceProtocol != 0xff &&
            ifc->bInterfaceProtocol != 16 &&
            ifc->bInterfaceProtocol != 17)
            continue;

        ctx->fd = fd;
        ctx->in_ep = in;
        ctx->out_ep = out;
        ctx->in_max_pkt_size = in_size;
        ctx->out_max_pkt_size = out_size;

        *intf = ifc->bInterfaceNumber;

        return 0;
    }

    return -ENOENT;
}

static int usb_open(struct qdl_device *ctx) {
    struct udev_enumerate *enumerate;
    struct udev_list_entry *devices;
    struct udev_list_entry *dev_list_entry;
    struct udev_monitor *mon;
    struct udev_device *dev;
    const char *dev_node;
    struct udev *udev;
    const char *path;
    struct usbdevfs_ioctl cmd;
    int mon_fd;
    int intf = -1;
    int ret;
    int fd;

    udev = udev_new();
    if (!udev)
        err(1, "failed to initialize udev");

    mon = udev_monitor_new_from_netlink(udev, "udev");
    udev_monitor_filter_add_match_subsystem_devtype(mon, "usb", NULL);
    udev_monitor_enable_receiving(mon);
    mon_fd = udev_monitor_get_fd(mon);

    enumerate = udev_enumerate_new(udev);
    udev_enumerate_add_match_subsystem(enumerate, "usb");
    udev_enumerate_scan_devices(enumerate);
    devices = udev_enumerate_get_list_entry(enumerate);

    udev_list_entry_foreach(dev_list_entry, devices) {
        path = udev_list_entry_get_name(dev_list_entry);
        dev = udev_device_new_from_syspath(udev, path);
        dev_node = udev_device_get_devnode(dev);

        if (!dev_node)
            continue;

        fd = open(dev_node, O_RDWR);
        if (fd < 0)
            continue;

        ret = parse_usb_desc(fd, ctx, &intf);
        if (!ret)
            goto found;

        close(fd);
    }

    fprintf(stderr, "Waiting for EDL device\n");

    for (;;) {
        fd_set read_fds;

        FD_ZERO(&read_fds);
        FD_SET(mon_fd, &read_fds);

        ret = select(mon_fd + 1, &read_fds, NULL, NULL, NULL);
        if (ret < 0)
            return -1;

        if (!FD_ISSET(mon_fd, &read_fds))
            continue;

        dev = udev_monitor_receive_device(mon);
        dev_node = udev_device_get_devnode(dev);

        if (!dev_node)
            continue;

        fd = open(dev_node, O_RDWR);
        if (fd < 0)
            continue;

        ret = parse_usb_desc(fd, ctx, &intf);
        if (!ret)
            goto found;

        close(fd);
    }

    found:
    udev_enumerate_unref(enumerate);
    udev_monitor_unref(mon);
    udev_unref(udev);

    cmd.ifno = intf;
    cmd.ioctl_code = USBDEVFS_DISCONNECT;
    cmd.data = NULL;

    ret = ioctl(ctx->fd, USBDEVFS_IOCTL, &cmd);
    if (ret && errno != ENODATA)
        err(1, "failed to disconnect kernel driver");

    ret = ioctl(ctx->fd, USBDEVFS_CLAIMINTERFACE, &intf);
    if (ret < 0)
        err(1, "failed to claim USB interface");

    return 0;
}

int qdl_read(struct qdl_device *ctx, void *buf, size_t len, unsigned int timeout) {
    struct usbdevfs_bulktransfer bulk = {};

    bulk.ep = ctx->in_ep;
    bulk.len = len;
    bulk.data = buf;
    bulk.timeout = timeout;

    return ioctl(ctx->fd, USBDEVFS_BULK, &bulk);
}

int qdl_write(struct qdl_device *ctx, const void *buf, size_t len) {

    unsigned char *data = (unsigned char *) buf;
    struct usbdevfs_bulktransfer bulk = {};
    int count = 0;
    size_t len_orig = len;
    int n;

    while (len > 0) {
        size_t xfer;
        xfer = (len > ctx->out_max_pkt_size * ctx->multiplier) ? ctx->out_max_pkt_size * ctx->multiplier : len;

        bulk.ep = ctx->out_ep;
        bulk.len = xfer;
        bulk.data = data;
        bulk.timeout = 1000;

        n = ioctl(ctx->fd, USBDEVFS_BULK, &bulk);
        if (n != xfer) {
            fprintf(stderr, "ERROR: n = %d, errno = %d (%s)\n",
                    n, errno, strerror(errno));
            if (errno == ENOMEM && ctx->multiplier != 1) {
                fprintf(stderr, "Buffer multiplier set to %lu. Try using smaller multiplier!\n", ctx->multiplier);
            }
            return -1;
        }
        count += (int) xfer;
        len -= xfer;
        data += xfer;
    }

    if (len_orig % ctx->out_max_pkt_size == 0) {
        bulk.ep = ctx->out_ep;
        bulk.len = 0;
        bulk.data = NULL;
        bulk.timeout = 1000;

        n = ioctl(ctx->fd, USBDEVFS_BULK, &bulk);
        if (n < 0)
            return n;
    }

    return count;
}

static void print_usage(const char *progname) {
    fprintf(stderr,
            "%s [--debug] [--multiplier 1-2048] [--storage <emmc|nand|ufs>] [--finalize-provisioning] [--include <PATH>] <prog.mbn> [<program> <patch> ...]\n",
            progname);
}

int main(int argc, char **argv) {
    char *prog_mbn, *storage = "ufs";
    char *incdir = NULL;
    int type;
    int ret;
    int opt;
    bool qdl_finalize_provisioning = false;
    qdl.multiplier = 128;
    qdl.pk_hash_len = 0;
    qdl.msm_id_len = 0;


    static struct option options[] = {
            {"debug",                 no_argument,       0, 'd'},
            {"include",               required_argument, 0, 'i'},
            {"finalize-provisioning", no_argument,       0, 'l'},
            {"storage",               required_argument, 0, 's'},
            {"multiplier",            required_argument, 0, 'm'},
            {0, 0,                                       0, 0}
    };

    while ((opt = getopt_long(argc, argv, "di:", options, NULL)) != -1) {
        switch (opt) {
            case 'd':
                qdl_debug = true;
                break;
            case 'i':
                incdir = optarg;
                break;
            case 'l':
                qdl_finalize_provisioning = true;
                break;
            case 's':
                storage = optarg;
                break;
            case 'm':
                qdl.multiplier = strtol(optarg, NULL, 10);
                if (qdl.multiplier >= 1 && qdl.multiplier <= 2048) {
                    continue;
                }
            default:
                print_usage(argv[0]);
                return 1;
        }
    }

    /* at least 2 non-optional args required */
    if ((optind + 2) > argc) {
        print_usage(argv[0]);
        return 1;
    }

    prog_mbn = argv[optind++];

    do {
        type = detect_type(argv[optind]);
        if (type < 0 || type == QDL_FILE_UNKNOWN)
            errx(1, "failed to detect file type of %s\n", argv[optind]);

        switch (type) {
            case QDL_FILE_PATCH:
                ret = patch_load(argv[optind]);
                if (ret < 0)
                    errx(1, "patch_load %s failed", argv[optind]);
                break;
            case QDL_FILE_PROGRAM:
                ret = program_load(argv[optind], !strcmp(storage, "nand"));
                if (ret < 0)
                    errx(1, "program_load %s failed", argv[optind]);
                break;
            case QDL_FILE_UFS:
                ret = ufs_load(argv[optind], qdl_finalize_provisioning);
                if (ret < 0)
                    errx(1, "ufs_load %s failed", argv[optind]);
                break;
            default:
                errx(1, "%s type not yet supported", argv[optind]);
        }
    } while (++optind < argc);

    ret = usb_open(&qdl);
    if (ret)
        return 1;

    qdl.mappings[0] = prog_mbn;
    ret = sahara_run(&qdl, qdl.mappings, true);
    if (ret < 0)
        return 1;

    ret = firehose_run(&qdl, incdir, storage);
    if (ret < 0)
        return 1;

    if (qdl.msm_id_len) {
        free(qdl.msm_id);
    }
    if (qdl.pk_hash_len) {
        free(qdl.pk_hash);
    }

    return 0;
}
