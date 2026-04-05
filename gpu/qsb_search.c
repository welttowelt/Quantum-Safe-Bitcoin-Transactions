/*
 * QSB Pinning Search — Fast C implementation
 * Uses libsecp256k1 for EC recovery + OpenMP for parallelism
 * 
 * Build: gcc -O3 -march=native -fopenmp -o qsb_pin qsb_pin.c \
 *        -lsecp256k1 -lcrypto -lm
 *
 * Usage: ./qsb_pin <sig_r_hex> <sig_s_hex> <sighash_prefix_hex> <difficulty> [max_attempts]
 *
 * For pinning: sighash_prefix contains the precomputed SHA-256 state
 * up to the locktime field. Each candidate finalizes with a different locktime.
 * 
 * For digest batch mode: reads z values from stdin, outputs hits.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>
#include <omp.h>

#include <secp256k1.h>
#include <secp256k1_recovery.h>
#include <openssl/sha.h>
#include <openssl/ripemd.h>

/* ============================================================
 * DER validity check (same logic as our Python code)
 * ============================================================ */

static int is_valid_der_sig(const unsigned char *data, int len) {
    if (len < 9) return 0;
    if (data[0] != 0x30) return 0;
    int total_len = data[1];
    if (total_len + 3 != len) return 0;
    unsigned char sighash = data[len - 1];
    if (sighash == 0 || sighash > 0x83) return 0;
    
    int idx = 2;
    for (int part = 0; part < 2; part++) {
        if (idx >= len - 1) return 0;
        if (data[idx] != 0x02) return 0;
        idx++;
        int int_len = data[idx];
        idx++;
        if (int_len == 0) return 0;
        if (idx + int_len > len - 1) return 0;
        if (int_len > 1 && data[idx] == 0x00 && !(data[idx + 1] & 0x80)) return 0;
        if (data[idx] & 0x80) return 0;
        idx += int_len;
    }
    if (idx != len - 1) return 0;
    return 1;
}

/* Easy mode DER checks */
static int is_valid_der_1_in_16(const unsigned char *data, int len) {
    return len >= 9 && (data[0] >> 4) == 3;
}

static int is_valid_der_1_in_256(const unsigned char *data, int len) {
    return len >= 9 && data[0] == 0x30;
}

static int is_valid_der_1_in_65536(const unsigned char *data, int len) {
    return len >= 9 && data[0] == 0x30 && data[1] == 0x11;
}

typedef int (*der_check_fn)(const unsigned char *, int);

/* ============================================================
 * SHA-256d (double SHA-256)
 * ============================================================ */

static void sha256d(const unsigned char *data, size_t len, unsigned char *out) {
    unsigned char tmp[32];
    SHA256(data, len, tmp);
    SHA256(tmp, 32, out);
}

/* ============================================================
 * Sighash computation for pinning
 * ============================================================ */

static void compute_pinning_sighash(
    const unsigned char *tx_prefix, int prefix_len,  /* everything before locktime */
    uint32_t locktime,
    unsigned char *sighash_out  /* 32 bytes */
) {
    /* Concatenate: tx_prefix + locktime(4 LE) + sighash_type(4 LE) */
    size_t total = prefix_len + 8;
    unsigned char *buf = (unsigned char *)malloc(total);
    memcpy(buf, tx_prefix, prefix_len);
    buf[prefix_len + 0] = (locktime >>  0) & 0xFF;
    buf[prefix_len + 1] = (locktime >>  8) & 0xFF;
    buf[prefix_len + 2] = (locktime >> 16) & 0xFF;
    buf[prefix_len + 3] = (locktime >> 24) & 0xFF;
    /* SIGHASH_ALL = 0x01 */
    buf[prefix_len + 4] = 0x01;
    buf[prefix_len + 5] = 0x00;
    buf[prefix_len + 6] = 0x00;
    buf[prefix_len + 7] = 0x00;
    
    sha256d(buf, total, sighash_out);
    free(buf);
}

/* ============================================================
 * EC Recovery + RIPEMD-160 + DER check
 * ============================================================ */

static int try_recover_and_check(
    const secp256k1_context *ctx,
    const unsigned char *sig_compact,  /* 64 bytes: r(32) + s(32) */
    const unsigned char *sighash,      /* 32 bytes */
    int recid,
    der_check_fn check_fn
) {
    secp256k1_ecdsa_recoverable_signature sig;
    if (!secp256k1_ecdsa_recoverable_signature_parse_compact(ctx, &sig, sig_compact, recid))
        return 0;
    
    secp256k1_pubkey pubkey;
    if (!secp256k1_ecdsa_recover(ctx, &pubkey, &sig, sighash))
        return 0;
    
    /* Compress pubkey */
    unsigned char pubkey_ser[33];
    size_t pubkey_len = 33;
    secp256k1_ec_pubkey_serialize(ctx, pubkey_ser, &pubkey_len, &pubkey, SECP256K1_EC_COMPRESSED);
    
    /* RIPEMD-160 of compressed pubkey */
    unsigned char ripemd_out[20];
    RIPEMD160(pubkey_ser, 33, ripemd_out);
    
    /* Check DER validity */
    return check_fn(ripemd_out, 20);
}

/* ============================================================
 * Pinning search
 * ============================================================ */

typedef struct {
    uint32_t locktime;
    int recid;
} hit_t;

static long long search_pinning(
    const unsigned char *tx_prefix, int prefix_len,
    const unsigned char *sig_compact,
    der_check_fn check_fn,
    uint32_t start_locktime, uint32_t count,
    hit_t *hits, int max_hits, int *num_hits
) {
    long long total_tried = 0;
    *num_hits = 0;
    
    #pragma omp parallel
    {
        secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
        
        #pragma omp for schedule(dynamic, 1024) reduction(+:total_tried)
        for (uint32_t i = 0; i < count; i++) {
            uint32_t lt = start_locktime + i;
            unsigned char sighash[32];
            compute_pinning_sighash(tx_prefix, prefix_len, lt, sighash);
            total_tried++;
            
            for (int recid = 0; recid < 2; recid++) {
                if (try_recover_and_check(ctx, sig_compact, sighash, recid, check_fn)) {
                    int idx;
                    #pragma omp atomic capture
                    idx = (*num_hits)++;
                    if (idx < max_hits) {
                        hits[idx].locktime = lt;
                        hits[idx].recid = recid;
                    }
                    break;
                }
            }
        }
        
        secp256k1_context_destroy(ctx);
    }
    
    return total_tried;
}

/* ============================================================
 * Batch digest search (reads z values from file)
 * ============================================================ */

static long long search_digest_batch(
    const unsigned char *sig_compact,
    der_check_fn check_fn,
    const char *z_file,
    int *hit_indices, int max_hits, int *num_hits
) {
    FILE *f = fopen(z_file, "rb");
    if (!f) {
        fprintf(stderr, "Cannot open %s\n", z_file);
        return 0;
    }
    
    /* Read all z values (32 bytes each) */
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);
    int n_values = fsize / 32;
    unsigned char *z_values = (unsigned char *)malloc(fsize);
    fread(z_values, 1, fsize, f);
    fclose(f);
    
    long long total_tried = 0;
    *num_hits = 0;
    
    #pragma omp parallel
    {
        secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
        
        #pragma omp for schedule(dynamic, 256) reduction(+:total_tried)
        for (int i = 0; i < n_values; i++) {
            total_tried++;
            for (int recid = 0; recid < 2; recid++) {
                if (try_recover_and_check(ctx, sig_compact, z_values + i * 32, recid, check_fn)) {
                    int idx;
                    #pragma omp atomic capture
                    idx = (*num_hits)++;
                    if (idx < max_hits) {
                        hit_indices[idx] = i;
                    }
                    break;
                }
            }
        }
        
        secp256k1_context_destroy(ctx);
    }
    
    free(z_values);
    return total_tried;
}

/* ============================================================
 * Hex helpers
 * ============================================================ */

static int hex_to_bytes(const char *hex, unsigned char *out, int max_len) {
    int len = strlen(hex) / 2;
    if (len > max_len) len = max_len;
    for (int i = 0; i < len; i++) {
        unsigned int byte;
        sscanf(hex + 2 * i, "%02x", &byte);
        out[i] = (unsigned char)byte;
    }
    return len;
}

/* ============================================================
 * Main
 * ============================================================ */

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage:\n");
        fprintf(stderr, "  Pinning: %s pin <sig_r_hex> <sig_s_hex> <tx_prefix_hex> <difficulty> [count]\n", argv[0]);
        fprintf(stderr, "  Digest:  %s digest <sig_r_hex> <sig_s_hex> <z_file> <difficulty>\n", argv[0]);
        fprintf(stderr, "\n  difficulty: 16, 256, 65536, or 0 for real\n");
        return 1;
    }
    
    const char *mode = argv[1];
    
    if (strcmp(mode, "pin") == 0 && argc >= 6) {
        /* Parse sig (r, s) as compact 64-byte format */
        unsigned char sig_compact[64];
        memset(sig_compact, 0, 64);
        unsigned char r_bytes[32], s_bytes[32];
        int r_len = hex_to_bytes(argv[2], r_bytes, 32);
        int s_len = hex_to_bytes(argv[3], s_bytes, 32);
        /* Right-pad to 32 bytes */
        memcpy(sig_compact + (32 - r_len), r_bytes, r_len);
        memcpy(sig_compact + 32 + (32 - s_len), s_bytes, s_len);
        
        /* Parse tx_prefix */
        int prefix_hex_len = strlen(argv[4]);
        int prefix_len = prefix_hex_len / 2;
        unsigned char *tx_prefix = (unsigned char *)malloc(prefix_len);
        hex_to_bytes(argv[4], tx_prefix, prefix_len);
        
        /* Difficulty */
        int diff = atoi(argv[5]);
        der_check_fn check_fn;
        switch (diff) {
            case 16:    check_fn = is_valid_der_1_in_16; break;
            case 256:   check_fn = is_valid_der_1_in_256; break;
            case 65536: check_fn = is_valid_der_1_in_65536; break;
            default:    check_fn = is_valid_der_sig; break;
        }
        
        uint32_t count = (argc >= 7) ? (uint32_t)atol(argv[6]) : 1000000;
        
        int num_threads = omp_get_max_threads();
        printf("QSB Pinning Search\n");
        printf("  Threads: %d\n", num_threads);
        printf("  Difficulty: 1/%d%s\n", diff ? diff : 0, diff ? "" : " (real ~2^46)");
        printf("  Prefix: %d bytes\n", prefix_len);
        printf("  Range: 0..%u\n", count);
        
        hit_t hits[1024];
        int num_hits = 0;
        
        double t0 = omp_get_wtime();
        long long tried = search_pinning(tx_prefix, prefix_len, sig_compact,
                                          check_fn, 0, count, hits, 1024, &num_hits);
        double elapsed = omp_get_wtime() - t0;
        
        double rate = tried / elapsed;
        printf("\n  Tried: %lld in %.2fs (%.0f/s, %.0f per thread)\n", 
               tried, elapsed, rate, rate / num_threads);
        printf("  Hits: %d\n", num_hits);
        for (int i = 0; i < num_hits && i < 10; i++) {
            printf("    locktime=%u recid=%d\n", hits[i].locktime, hits[i].recid);
        }
        
        /* Extrapolation */
        double target_2_46 = 70368744177664.0; /* 2^46 */
        double hours_real = target_2_46 / rate / 3600.0;
        printf("\n  Extrapolation to real (2^46):\n");
        printf("    This machine: %.0f hours (%.0f days)\n", hours_real, hours_real / 24);
        printf("    Cost @ $0.15/hr: $%.0f\n", hours_real * 0.15);
        for (int n = 10; n <= 100; n *= 5) {
            printf("    %d machines: %.0f hours, $%.0f\n", n, hours_real / n, hours_real * 0.15);
        }
        
        free(tx_prefix);
        
    } else if (strcmp(mode, "digest") == 0 && argc >= 6) {
        unsigned char sig_compact[64];
        memset(sig_compact, 0, 64);
        unsigned char r_bytes[32], s_bytes[32];
        int r_len = hex_to_bytes(argv[2], r_bytes, 32);
        int s_len = hex_to_bytes(argv[3], s_bytes, 32);
        memcpy(sig_compact + (32 - r_len), r_bytes, r_len);
        memcpy(sig_compact + 32 + (32 - s_len), s_bytes, s_len);
        
        const char *z_file = argv[4];
        int diff = atoi(argv[5]);
        der_check_fn check_fn;
        switch (diff) {
            case 16:    check_fn = is_valid_der_1_in_16; break;
            case 256:   check_fn = is_valid_der_1_in_256; break;
            case 65536: check_fn = is_valid_der_1_in_65536; break;
            default:    check_fn = is_valid_der_sig; break;
        }
        
        int num_threads = omp_get_max_threads();
        printf("QSB Digest Search (batch)\n");
        printf("  Threads: %d\n", num_threads);
        printf("  Z-values file: %s\n", z_file);
        
        int hit_indices[1024];
        int num_hits = 0;
        
        double t0 = omp_get_wtime();
        long long tried = search_digest_batch(sig_compact, check_fn, z_file,
                                               hit_indices, 1024, &num_hits);
        double elapsed = omp_get_wtime() - t0;
        
        double rate = tried / elapsed;
        printf("\n  Tried: %lld in %.2fs (%.0f/s)\n", tried, elapsed, rate);
        printf("  Hits: %d\n", num_hits);
        for (int i = 0; i < num_hits && i < 10; i++) {
            printf("    z_index=%d\n", hit_indices[i]);
        }
        
    } else if (strcmp(mode, "bench") == 0) {
        /* Quick benchmark: just measure EC recovery rate */
        int num_threads = omp_get_max_threads();
        int count = 1000000;
        printf("QSB Benchmark\n");
        printf("  Threads: %d\n", num_threads);
        printf("  Count: %d\n", count);
        
        /* Random sig */
        unsigned char sig_compact[64];
        for (int i = 0; i < 64; i++) sig_compact[i] = (unsigned char)(i + 1);
        
        long long total = 0;
        double t0 = omp_get_wtime();
        
        #pragma omp parallel
        {
            secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
            
            #pragma omp for schedule(static) reduction(+:total)
            for (int i = 0; i < count; i++) {
                unsigned char msg[32];
                /* Quick pseudo-random hash */
                uint32_t v = (uint32_t)i;
                for (int j = 0; j < 8; j++) {
                    v = v * 1103515245 + 12345;
                    msg[j*4+0] = (v >> 0) & 0xFF;
                    msg[j*4+1] = (v >> 8) & 0xFF;
                    msg[j*4+2] = (v >> 16) & 0xFF;
                    msg[j*4+3] = (v >> 24) & 0xFF;
                }
                
                secp256k1_ecdsa_recoverable_signature sig;
                if (secp256k1_ecdsa_recoverable_signature_parse_compact(ctx, &sig, sig_compact, 0)) {
                    secp256k1_pubkey pubkey;
                    if (secp256k1_ecdsa_recover(ctx, &pubkey, &sig, msg)) {
                        unsigned char pub_ser[33];
                        size_t pub_len = 33;
                        secp256k1_ec_pubkey_serialize(ctx, pub_ser, &pub_len, &pubkey, SECP256K1_EC_COMPRESSED);
                        
                        unsigned char rmd[20];
                        RIPEMD160(pub_ser, 33, rmd);
                        total++;
                    }
                }
            }
            
            secp256k1_context_destroy(ctx);
        }
        
        double elapsed = omp_get_wtime() - t0;
        double rate = total / elapsed;
        double per_us = elapsed / total * 1e6;
        
        printf("\n  %lld recoveries in %.2fs\n", total, elapsed);
        printf("  Rate: %.0f/s (%.1f μs each)\n", rate, per_us);
        printf("  Per thread: %.0f/s\n", rate / num_threads);
        
        double target = 70368744177664.0; /* 2^46 */
        printf("\n  Extrapolation to 2^46:\n");
        printf("    This machine: %.0f hours (%.0f days)\n", target/rate/3600, target/rate/3600/24);
        printf("    Cost @ $0.50/hr: $%.0f\n", target/rate/3600 * 0.50);
        
    } else {
        fprintf(stderr, "Unknown mode: %s\n", mode);
        return 1;
    }
    
    return 0;
}
