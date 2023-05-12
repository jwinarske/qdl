#ifndef QDL_H
#define QDL_H

#include <stdbool.h>
#include <stdint.h>

#include "patch.h"
#include "program.h"
#include <libxml/tree.h>

#define MAPPING_SZ 64

struct qdl_device {
    int fd;

    int in_ep;
    int out_ep;

    __attribute__((unused)) size_t in_max_pkt_size;
    size_t out_max_pkt_size;

    size_t multiplier;

    char *mappings[MAPPING_SZ]; // array index is the id from the device

    uint32_t serial;
    uint32_t msm_id_len;
    uint8_t *msm_id;
    uint32_t pk_hash_len;
    uint8_t *pk_hash;
};

int qdl_read(struct qdl_device *ctx, void *buf, size_t len, unsigned int timeout);

int qdl_write(struct qdl_device *ctx, const void *buf, size_t len);

int firehose_run(struct qdl_device *ctx, const char *incdir, const char *storage);

int sahara_run(struct qdl_device *ctx, char *img_arr[], bool single_image);

void print_hex_dump(const char *prefix, const void *buf, size_t len);

unsigned attr_as_unsigned(xmlNode *node, const char *attr, int *errors);

const char *attr_as_string(xmlNode *node, const char *attr, int *errors);

extern bool qdl_debug;

#endif  /* QDL_H */
