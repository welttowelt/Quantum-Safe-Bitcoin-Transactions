/*
 * qsb_params.h — Binary parameter file reader for QSB GPU search
 *
 * File formats:
 *
 * pinning.bin:
 *   [4: total_preimage_len]
 *   [4: tail_data_len]
 *   [32: midstate (8 × uint32 big-endian)]
 *   [tail_data_len: tail bytes]
 *   [32: neg_r_inv LE]
 *   [32: u2r_x LE]
 *   [32: u2r_y LE]
 *
 * digest_rN.bin:
 *   [4: n (pool size)]
 *   [4: t (selection size)]
 *   [4: total_preimage_len]
 *   [4: tail_section_len]
 *   [4: tx_suffix_len]
 *   [32: midstate (8 × uint32 big-endian)]
 *   [n*10: dummy_sigs in script order]
 *   [tail_section_len: tail section]
 *   [tx_suffix_len: tx suffix]
 *   [32: neg_r_inv LE]
 *   [32: u2r_x LE]
 *   [32: u2r_y LE]
 */

#ifndef QSB_PARAMS_H
#define QSB_PARAMS_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

typedef struct {
    uint32_t total_preimage_len;
    uint32_t tail_data_len;
    uint32_t midstate[8];
    uint8_t *tail_data;
    uint8_t neg_r_inv[32];
    uint8_t u2r_x[32];
    uint8_t u2r_y[32];
} pinning_params_t;

typedef struct {
    uint32_t n;
    uint32_t t;
    uint32_t total_preimage_len;
    uint32_t tail_section_len;
    uint32_t tx_suffix_len;
    uint32_t midstate[8];
    uint8_t *dummy_sigs;     /* n * 10 bytes */
    uint8_t *tail_section;
    uint8_t *tx_suffix;
    uint8_t neg_r_inv[32];
    uint8_t u2r_x[32];
    uint8_t u2r_y[32];
} digest_params_t;

static int load_pinning_params(const char *filename, pinning_params_t *p) {
    FILE *f = fopen(filename, "rb");
    if (!f) { fprintf(stderr, "Cannot open %s\n", filename); return -1; }
    
    if (fread(&p->total_preimage_len, 4, 1, f) != 1) goto err;
    if (fread(&p->tail_data_len, 4, 1, f) != 1) goto err;
    if (fread(p->midstate, 4, 8, f) != 8) goto err;
    
    /* Convert midstate from file big-endian to host uint32 */
    for (int i = 0; i < 8; i++) {
        uint8_t *b = (uint8_t *)&p->midstate[i];
        p->midstate[i] = ((uint32_t)b[0]<<24)|((uint32_t)b[1]<<16)|((uint32_t)b[2]<<8)|b[3];
    }
    
    p->tail_data = (uint8_t *)malloc(p->tail_data_len);
    if (fread(p->tail_data, 1, p->tail_data_len, f) != p->tail_data_len) goto err;
    if (fread(p->neg_r_inv, 1, 32, f) != 32) goto err;
    if (fread(p->u2r_x, 1, 32, f) != 32) goto err;
    if (fread(p->u2r_y, 1, 32, f) != 32) goto err;
    
    fclose(f);
    printf("  Loaded pinning params: preimage=%u, tail=%u\n",
           p->total_preimage_len, p->tail_data_len);
    return 0;
    
err:
    fprintf(stderr, "Error reading %s\n", filename);
    fclose(f);
    return -1;
}

static int load_digest_params(const char *filename, digest_params_t *p) {
    FILE *f = fopen(filename, "rb");
    if (!f) { fprintf(stderr, "Cannot open %s\n", filename); return -1; }
    
    if (fread(&p->n, 4, 1, f) != 1) goto err;
    if (fread(&p->t, 4, 1, f) != 1) goto err;
    if (fread(&p->total_preimage_len, 4, 1, f) != 1) goto err;
    if (fread(&p->tail_section_len, 4, 1, f) != 1) goto err;
    if (fread(&p->tx_suffix_len, 4, 1, f) != 1) goto err;
    if (fread(p->midstate, 4, 8, f) != 8) goto err;
    
    for (int i = 0; i < 8; i++) {
        uint8_t *b = (uint8_t *)&p->midstate[i];
        p->midstate[i] = ((uint32_t)b[0]<<24)|((uint32_t)b[1]<<16)|((uint32_t)b[2]<<8)|b[3];
    }
    
    p->dummy_sigs = (uint8_t *)malloc(p->n * 10);
    if (fread(p->dummy_sigs, 1, p->n * 10, f) != p->n * 10) goto err;
    
    p->tail_section = (uint8_t *)malloc(p->tail_section_len);
    if (fread(p->tail_section, 1, p->tail_section_len, f) != p->tail_section_len) goto err;
    
    p->tx_suffix = (uint8_t *)malloc(p->tx_suffix_len);
    if (fread(p->tx_suffix, 1, p->tx_suffix_len, f) != p->tx_suffix_len) goto err;
    
    if (fread(p->neg_r_inv, 1, 32, f) != 32) goto err;
    if (fread(p->u2r_x, 1, 32, f) != 32) goto err;
    if (fread(p->u2r_y, 1, 32, f) != 32) goto err;
    
    fclose(f);
    printf("  Loaded digest params: n=%u, t=%u, preimage=%u, tail=%u, suffix=%u\n",
           p->n, p->t, p->total_preimage_len, p->tail_section_len, p->tx_suffix_len);
    return 0;
    
err:
    fprintf(stderr, "Error reading %s\n", filename);
    fclose(f);
    return -1;
}

static void free_pinning_params(pinning_params_t *p) {
    free(p->tail_data);
}

static void free_digest_params(digest_params_t *p) {
    free(p->dummy_sigs);
    free(p->tail_section);
    free(p->tx_suffix);
}

#endif /* QSB_PARAMS_H */
