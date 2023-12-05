/*
    Implementation of Chow's Whitebox AES
        - Generate a encryption table of WBAES-128
*/

#include <iostream>
#include <fstream>
#include <cstdlib>
#include <ctime>

#include "wbaes_tables.h"
#include "gf2_mat.h"

extern uint8_t         Sbox[256];
extern uint8_t     shift_map[16];
extern uint8_t inv_shift_map[16];

static void knuth_shuffle(uint8_t *x) {
    int i, j;
    uint8_t temp;

    // std::srand(std::time(nullptr));

    for (i = 0; i < 16; i++) {
        j = std::rand() % 16;        // Replace this with secure pseudo-random number generator
        
        temp = x[i];
        x[i] = x[j];
        x[j] = temp;
    }
}

static void get_inv(const uint8_t *x, uint8_t *inv_x) {
    int i;

    for (i = 0; i < 16; i++) {
        inv_x[x[i]] = i;
    }
}

static void gen_rand(uint8_t *x, uint8_t *inv_x) {
    int i;

    for (i = 0; i < 16; i++) {
        x[i] = i;
    }

    knuth_shuffle(x);

    if (inv_x) {
        get_inv(x, inv_x);
    }
}

static void shift_rows(uint8_t *x) {
    int i;
    uint8_t temp[16];

    memcpy(temp, x, 16);

    for (i = 0; i < 16; i++) {
        x[i] = temp[shift_map[i]];
    }
}

static void inv_shift_rows(uint8_t *x) {
    int i;
    uint8_t temp[16];

    memcpy(temp, x, 16);

    for (i = 0; i < 16; i++) {
        x[i] = temp[inv_shift_map[i]];
    }
}

static void add_rk(uint8_t *x, uint32_t *rk) {
    int i;
    uint8_t u8_rk[16];

    /* 
        Sync Endian
    */    
    PUTU32(u8_rk     , rk[0]);
    PUTU32(u8_rk +  4, rk[1]);
    PUTU32(u8_rk +  8, rk[2]);
    PUTU32(u8_rk + 12, rk[3]);

    for (i = 0; i < 16; i++) {
        x[i] ^= u8_rk[shift_map[i]];
    }
}

void encode_ext_x(uint8_t (*f)[2][16], uint8_t *x) {
    int i;

    for (i = 0; i < 16; i++) {
        x[i] = f[i][1][(x[i] >> 4) & 0xf] << 4 | f[i][0][x[i] & 0xf];
    }
}

void decode_ext_x(uint8_t (*inv_f)[2][16], uint8_t *x) {
    int i;

    for (i = 0; i < 16; i++) {
        x[i] = inv_f[i][1][(x[i] >> 4) & 0xf] << 4 | inv_f[i][0][x[i] & 0xf];
    }
}

void gen_nonlinear_encoding(WBAES_NONLINEAR_ENCODING &en) {
    int i, j, k, n;

    /*
        External Encoding
    */
    for (i = 0; i < 16; i++) {
        for (j = 0; j < 2; j++) {
            gen_rand(en.ext_f[i][j], en.inv_ext_f[i][j]);
        }
    }

    /*
        Internal Encoding (IA, XOR-128 x 15)
         - IA   16 x 2 x 16
         - XOR  15 x 32 x 16
    */
    for (i = 0; i < 16; i++) {      // encoding for the output of IA-tables
        for (j = 0; j < 2; j++) {
            gen_rand(en.int_f[i][j], en.inv_int_f[i][j]);
        }
    }

    for (i = 0; i < 8; i++) {
        for (j = 0; j < 16; j++) {
            k = i << 1;
            n = j << 1;

            memcpy(en.int_xf[i][n], en.inv_int_f[k  ][1], 16); memcpy(en.int_xf[i][n+1], en.inv_int_f[k  ][0], 16);
            memcpy(en.int_yf[i][n], en.inv_int_f[k+1][1], 16); memcpy(en.int_yf[i][n+1], en.inv_int_f[k+1][0], 16);
            // dump_bytes(en.int_xf[i][n], 16);
            // dump_bytes(en.int_xf[i][n], 16);
        }
    }

    for (i = 0; i < 15; i++) {      // encoding for the output of xor-tables
        for (j = 0; j < 32; j++) {
            gen_rand(en.int_outf[i][j], en.inv_int_outf[i][j]);
        }
    }
    memcpy(en.int_xf[ 8], en.inv_int_outf[ 0], 512); memcpy(en.int_yf[ 8], en.inv_int_outf[ 1], 512);
    memcpy(en.int_xf[ 9], en.inv_int_outf[ 2], 512); memcpy(en.int_yf[ 9], en.inv_int_outf[ 3], 512);
    memcpy(en.int_xf[10], en.inv_int_outf[ 4], 512); memcpy(en.int_yf[10], en.inv_int_outf[ 5], 512);
    memcpy(en.int_xf[11], en.inv_int_outf[ 6], 512); memcpy(en.int_yf[11], en.inv_int_outf[ 7], 512);
    memcpy(en.int_xf[12], en.inv_int_outf[ 8], 512); memcpy(en.int_yf[12], en.inv_int_outf[ 9], 512);
    memcpy(en.int_xf[13], en.inv_int_outf[10], 512); memcpy(en.int_yf[13], en.inv_int_outf[11], 512);
    memcpy(en.int_xf[14], en.inv_int_outf[12], 512); memcpy(en.int_yf[14], en.inv_int_outf[13], 512);

    /*
        Internal Encoding - I
         - Ty-Boxes  9 x 16 x 8 x 16
         - XOR
    */
    for (i = 0; i < 9; i++) {       // encoding for the output of ty-boxes
        for (j = 0; j < 16; j++) {
            for (k = 0; k < 8; k++) {
                gen_rand(en.int_s[i][j][k], en.inv_int_s[i][j][k]);
            }
        }
    }

    for (i = 0; i < 9; i++) {
        for (j = 0; j < 8; j++) {
            memcpy(en.int_xs[i][j], en.inv_int_s[i][j*2  ], 128);
            memcpy(en.int_ys[i][j], en.inv_int_s[i][j*2+1], 128);
        }
    }

    for (i = 0; i < 9; i++) {       // encoding for the output of xor-tables
        for (j = 0; j < 12; j++) {
            for (k = 0; k < 8; k++) {
                gen_rand(en.int_outs[i][j][k], en.inv_int_outs[i][j][k]);
            }
        }
    }

    for (i = 0; i < 9; i++) {
        memcpy(en.int_xs[i][ 8], en.inv_int_outs[i][0], 128); memcpy(en.int_ys[i][ 8], en.inv_int_outs[i][1], 128);
        memcpy(en.int_xs[i][ 9], en.inv_int_outs[i][2], 128); memcpy(en.int_ys[i][ 9], en.inv_int_outs[i][3], 128);
        memcpy(en.int_xs[i][10], en.inv_int_outs[i][4], 128); memcpy(en.int_ys[i][10], en.inv_int_outs[i][5], 128);
        memcpy(en.int_xs[i][11], en.inv_int_outs[i][6], 128); memcpy(en.int_ys[i][11], en.inv_int_outs[i][7], 128);
    }

    /*
        Internal Encoding - II
         - MBL-tables  9 x 16 x 8 x 16
         - XOR
    */
    for (i = 0; i < 9; i++) {       // encoding for the output of mbl-tables
        for (j = 0; j < 16; j++) {
            for (k = 0; k < 8; k++) {
                gen_rand(en.int_m[i][j][k], en.inv_int_m[i][j][k]);
            }
        }
    }

    for (i = 0; i < 9; i++) {
        for (j = 0; j < 8; j++) {
            memcpy(en.int_xm[i][j], en.inv_int_m[i][j*2  ], 128);
            memcpy(en.int_ym[i][j], en.inv_int_m[i][j*2+1], 128);
        }
    }

    for (i = 0; i < 9; i++) {       // encoding for the output of xor-tables
        for (j = 0; j < 12; j++) {
            for (k = 0; k < 8; k++) {
                gen_rand(en.int_outm[i][j][k], en.inv_int_outm[i][j][k]);
            }
        }
    }

    for (i = 0; i < 9; i++) {
        memcpy(en.int_xm[i][ 8], en.inv_int_outm[i][0], 128); memcpy(en.int_ym[i][ 8], en.inv_int_outm[i][1], 128);
        memcpy(en.int_xm[i][ 9], en.inv_int_outm[i][2], 128); memcpy(en.int_ym[i][ 9], en.inv_int_outm[i][3], 128);
        memcpy(en.int_xm[i][10], en.inv_int_outm[i][4], 128); memcpy(en.int_ym[i][10], en.inv_int_outm[i][5], 128);
        memcpy(en.int_xm[i][11], en.inv_int_outm[i][6], 128); memcpy(en.int_ym[i][11], en.inv_int_outm[i][7], 128);
    }

    /*
        Internal Encoding - IV
         xor_tables
          12 x 8 tables for each round
          |01 02| |03 04| |05 06| |07 08| |09 10| |11 12| |13 14| |15 16|
             |       |       |       |       |       |       |       |
             1       2       3       4       5       6       7       8
              \     /         \     /         \     /         \     / 
                 9               10              11              12
    */
    
}

void gen_xor_tables(uint8_t (*s_xor_tables)[16][16], uint8_t (*r1_xor_tables)[96][16][16], uint8_t (*r2_xor_tables)[96][16][16], uint8_t (*e_xor_tables)[16][16], const WBAES_NONLINEAR_ENCODING &en) {
    int r, n, x, y;

    /*
        Ty-Boxes -> XOR-32
    */
    for (r = 0; r < 9; r++) {
        for (n = 0; n < 96; n++) {
            int i = n >> 3;     // 0 1 ... 11
            int j = n % 8;      // 0 1 ...  7

            for (x = 0; x < 16; x++) {
                for (y = 0; y < 16; y++) {
                    // if (i >= 8) {
                    //     // printf("%d ", n);
                    //     r1_xor_tables[r][n][x][y] = en.int_xs[r][i][j][x] ^ en.int_ys[r][i][j][y];
                    // }
                    // else {
                    //     r1_xor_tables[r][n][x][y] = en.int_outs[r][i][j][en.int_xs[r][i][j][x] ^ en.int_ys[r][i][j][y]];
                    // }
                    r1_xor_tables[r][n][x][y] = en.int_outs[r][i][j][en.int_xs[r][i][j][x] ^ en.int_ys[r][i][j][y]];
                    // r1_xor_tables[r][n][x][y] = en.int_xs[r][i][j][x] ^ en.int_ys[r][i][j][y];
                    // r1_xor_tables[r][n][x][y] = x ^ y;
                }
            }
        }
    }

    /*
        MBL-tables -> XOR-32
    */
    for (r = 0; r < 9; r++) {
        for (n = 0; n < 96; n++) {
            int i = n >> 3;     // 0 1 ... 11
            int j = n % 8;      // 0 1 ...  7

            for (x = 0; x < 16; x++) {
                for (y = 0; y < 16; y++) {
                    if (r == 8 && i >= 8) {
                        r2_xor_tables[r][n][x][y] = en.int_xm[r][i][j][x] ^ en.int_ym[r][i][j][y];
                    }
                    else {
                        r2_xor_tables[r][n][x][y] = en.int_outm[r][i][j][en.int_xm[r][i][j][x] ^ en.int_ym[r][i][j][y]];
                    }
                    // r2_xor_tables[r][n][x][y] = en.int_outm[r][i][j][en.int_xm[r][i][j][x] ^ en.int_ym[r][i][j][y]];
                    // r2_xor_tables[r][n][x][y] = x ^ y;
                }
            }
        }
    }
    
    /*
        IA type -> XOR-128
    */
    for (n = 0; n < 480; n++) {
        int i = n >> 5;     // 0 1 ... 14
        int j = n % 32;     // 0 1 ... 31

        for (x = 0; x < 16; x++) {
            for (y = 0; y < 16; y++) {
                s_xor_tables[n][x][y] = en.int_outf[i][j][(en.int_xf[i][j][x]) ^ (en.int_yf[i][j][y])];
            }
        }
    }

    // for (n = 448; n < 480; n++) {
    //     for(x = 0; x < 16; x++) {
    //         for (y = 0; y < 16; y++) {
    //             s_xor_tables[n][x][y] = en.int_outf[14][n%32][en.int_xf[14][(n%32)][x] ^ en.int_yf[14][(n%32)][y]];
    //         }
    //     }
    // }
}

void gen_t_boxes(uint8_t (*t_boxes)[16][256], uint32_t *roundkeys) {
    int r, x, n;
    uint8_t temp[16];

    for (r = 0; r < 10; r++) {
        for (x = 0; x < 256; x++) {
            memset(temp, x, 16);
            add_rk(temp, &roundkeys[4*r]);          // temp ^ shift_rows(RK)

            for (n = 0; n < 16; n++) {
                t_boxes[r][n][x] = Sbox[temp[n]];   // sbox(temp ^ shift_rows(RK))
            }
        }
    }

    /*
        Final Round
         sbox(temp ^ shift_rows(RK_10)) ^ RK_11
    */
    for (n = 0; n < 4; n++) {
        for (x = 0; x < 256; x++) { 
            t_boxes[9][n*4  ][x] ^= roundkeys[40+n] >> 24;
            t_boxes[9][n*4+1][x] ^= roundkeys[40+n] >> 16;
            t_boxes[9][n*4+2][x] ^= roundkeys[40+n] >>  8;
            t_boxes[9][n*4+3][x] ^= roundkeys[40+n]      ;
        }
    }
}

void gen_tyi_tables(uint32_t (*tyi_tables)[256]) {
    int x;

    for (x = 0; x < 256; x++) {
        tyi_tables[0][x] = (GF_mul(2, x) << 24) |           (x  << 16) |           (x  << 8) | GF_mul(3, x);
        tyi_tables[1][x] = (GF_mul(3, x) << 24) | (GF_mul(2, x) << 16) |           (x  << 8) |          (x);
        tyi_tables[2][x] =           (x  << 24) | (GF_mul(3, x) << 16) | (GF_mul(2, x) << 8) |          (x);
        tyi_tables[3][x] =           (x  << 24) |           (x  << 16) | (GF_mul(3, x) << 8) | GF_mul(2, x);
    }
}

void composite_t_tyi(uint8_t (*t_boxes)[16][256], uint32_t (*tyi_tables)[256], uint32_t (*ty_boxes)[16][256], uint8_t (*last_box)[256]) {
    int r, n, x;

    /* Round 1-9 */
    for (r = 0; r < 9; r++) {
        for (x = 0; x < 256; x++) {
            for (n = 0; n < 16; n++) {
                ty_boxes[r][n][x] = tyi_tables[n%4][t_boxes[r][n][x]];
            }
        }
    }

    /* Round 10 */
    memcpy(last_box, t_boxes[9], 16 * 256);
}

void apply_encoding(WBAES_ENCRYPTION_TABLE &et, WBAES_NONLINEAR_ENCODING &en) {
    uint8_t   u8_temp[256];
    uint32_t u32_temp[256];
    NTL::mat_GF2 mb[9][4], l[10][16], l0[16], cl0;

    int r, n, x;

    /*
        Linear Encoding
         - (MB) Inverible 32x32 matrix
         - (L)  Inverible 8x8 matrix
    */
    uint8_t  t1, t2, t3, t4;
    uint32_t wt1, wt2;

    for (r = 0; r < 9; r++) {
        /*
            Initializes Invertible Matrix (MB)
             - size       : 32 x 32
             - components : GF2
             - determinant: !0
        */
        mb[r][0] = gen_gf2_rand_invertible_matrix(32);
        mb[r][1] = gen_gf2_rand_invertible_matrix(32);
        mb[r][2] = gen_gf2_rand_invertible_matrix(32);
        mb[r][3] = gen_gf2_rand_invertible_matrix(32);

        /*
            Applies Mixing Bijection
        */
        for (x = 0; x < 256; x++) {
            for (n = 0; n < 16; n++) {
                et.ty_boxes[r][n][x] = mul<uint32_t>(mb[r][n/4], et.ty_boxes[r][n][x]);

                // wt1 = (uint32_t)(x << (24 - (8 * (n % 4))));
                // wt2 = (
                //     en.inv_int_outs[r][8+(n>>2)][0][(wt1 >> 28) & 0xf] << 28 | en.inv_int_outs[r][8+(n>>2)][1][(wt1 >> 24) & 0xf] << 24 |
                //     en.inv_int_outs[r][8+(n>>2)][2][(wt1 >> 20) & 0xf] << 20 | en.inv_int_outs[r][8+(n>>2)][3][(wt1 >> 16) & 0xf] << 16 |
                //     en.inv_int_outs[r][8+(n>>2)][4][(wt1 >> 12) & 0xf] << 12 | en.inv_int_outs[r][8+(n>>2)][5][(wt1 >>  8) & 0xf] <<  8 |
                //     en.inv_int_outs[r][8+(n>>2)][6][(wt1 >>  4) & 0xf] <<  4 | en.inv_int_outs[r][8+(n>>2)][7][(wt1      ) & 0xf]     
                // );
                // et.mbl_tables[r][n][x] = mul<uint32_t>(NTL::inv(mb[r][n/4]), wt2);
                et.mbl_tables[r][n][x] = mul<uint32_t>(NTL::inv(mb[r][n/4]), (uint32_t)(x << (24 - (8 * (n % 4)))));
            }
        }
    }

    /*
        Applies L at each round
    */

    for (r = 0; r < 9; r++) {
        /*
            Initializes Invertible Matrix (L)
                - size       : 8 x 8
                - components : GF2
                - determinant: !0
        */
        l[r][0 ] = gen_gf2_rand_invertible_matrix(8); l[r][1 ] = gen_gf2_rand_invertible_matrix(8);
        l[r][2 ] = gen_gf2_rand_invertible_matrix(8); l[r][3 ] = gen_gf2_rand_invertible_matrix(8);
        l[r][4 ] = gen_gf2_rand_invertible_matrix(8); l[r][5 ] = gen_gf2_rand_invertible_matrix(8);
        l[r][6 ] = gen_gf2_rand_invertible_matrix(8); l[r][7 ] = gen_gf2_rand_invertible_matrix(8);
        l[r][8 ] = gen_gf2_rand_invertible_matrix(8); l[r][9 ] = gen_gf2_rand_invertible_matrix(8);
        l[r][10] = gen_gf2_rand_invertible_matrix(8); l[r][11] = gen_gf2_rand_invertible_matrix(8);
        l[r][12] = gen_gf2_rand_invertible_matrix(8); l[r][13] = gen_gf2_rand_invertible_matrix(8);
        l[r][14] = gen_gf2_rand_invertible_matrix(8); l[r][15] = gen_gf2_rand_invertible_matrix(8);
        
        for (n = 0; n < 16; ++n) {
            for (x = 0; x < 256; x++) {
                uint8_t y = en.inv_int_outs[r][8+(n/4)][(n%4)*2][(x >> 4) & 0xf] << 4 | en.inv_int_outs[r][8+(n/4)][(n%4)*2+1][x & 0xf];
                t1 = mul<uint8_t>(l[r][inv_shift_map[(4*(n/4))  ]], (uint8_t)(et.mbl_tables[r][n][y] >> 24));
                t2 = mul<uint8_t>(l[r][inv_shift_map[(4*(n/4))+1]], (uint8_t)(et.mbl_tables[r][n][y] >> 16));
                t3 = mul<uint8_t>(l[r][inv_shift_map[(4*(n/4))+2]], (uint8_t)(et.mbl_tables[r][n][y] >>  8));
                t4 = mul<uint8_t>(l[r][inv_shift_map[(4*(n/4))+3]], (uint8_t)(et.mbl_tables[r][n][y]      ));

                et.mbl_tables[r][n][x] = (
                    en.int_m[r][n][0][(t1 >> 4) & 0xf] << 28 | en.int_m[r][n][1][t1 & 0xf] << 24 |
                    en.int_m[r][n][2][(t2 >> 4) & 0xf] << 20 | en.int_m[r][n][3][t2 & 0xf] << 16 |
                    en.int_m[r][n][4][(t3 >> 4) & 0xf] << 12 | en.int_m[r][n][5][t3 & 0xf] <<  8 |
                    en.int_m[r][n][6][(t4 >> 4) & 0xf] <<  4 | en.int_m[r][n][7][t4 & 0xf]
                );

                // et.mbl_tables[r][n][x] = (
                //     en.int_m[r][n][0][(t1 >> 4) & 0xf] << 28 | en.int_m[r][n][1][t1 & 0xf] << 24 |
                //     en.int_m[r][n][2][(t2 >> 4) & 0xf] << 20 | en.int_m[r][n][3][t2 & 0xf] << 16 |
                //     en.int_m[r][n][4][(t3 >> 4) & 0xf] << 12 | en.int_m[r][n][5][t3 & 0xf] <<  8 |
                //     en.int_m[r][n][6][(t4 >> 4) & 0xf] <<  4 | en.int_m[r][n][7][t4 & 0xf]        
                // );

                // et.mbl_tables[r][n][x] = (
                //     mul<uint8_t>(l[r][inv_shift_map[(4*(n/4))  ]], (uint8_t)(et.mbl_tables[r][n][x] >> 24)) << 24 |
                //     mul<uint8_t>(l[r][inv_shift_map[(4*(n/4))+1]], (uint8_t)(et.mbl_tables[r][n][x] >> 16)) << 16 |
                //     mul<uint8_t>(l[r][inv_shift_map[(4*(n/4))+2]], (uint8_t)(et.mbl_tables[r][n][x] >>  8)) <<  8 |
                //     mul<uint8_t>(l[r][inv_shift_map[(4*(n/4))+3]], (uint8_t)(et.mbl_tables[r][n][x]      ))       
                // );
            }
        }
    }

    /*
        Applies L to inverse of L at previous round
    */
    l0[0 ] = gen_gf2_rand_invertible_matrix(8); l0[1 ] = gen_gf2_rand_invertible_matrix(8);
    l0[2 ] = gen_gf2_rand_invertible_matrix(8); l0[3 ] = gen_gf2_rand_invertible_matrix(8);
    l0[4 ] = gen_gf2_rand_invertible_matrix(8); l0[5 ] = gen_gf2_rand_invertible_matrix(8);
    l0[6 ] = gen_gf2_rand_invertible_matrix(8); l0[7 ] = gen_gf2_rand_invertible_matrix(8);
    l0[8 ] = gen_gf2_rand_invertible_matrix(8); l0[9 ] = gen_gf2_rand_invertible_matrix(8);
    l0[10] = gen_gf2_rand_invertible_matrix(8); l0[11] = gen_gf2_rand_invertible_matrix(8);
    l0[12] = gen_gf2_rand_invertible_matrix(8); l0[13] = gen_gf2_rand_invertible_matrix(8);
    l0[14] = gen_gf2_rand_invertible_matrix(8); l0[15] = gen_gf2_rand_invertible_matrix(8);

    for (r = 0; r < 16; r++) {
        for (x = 0; x < 256; x++) {
            uint8_t y = en.inv_ext_f[r][1][(x >> 4) & 0xf] << 4 | en.inv_ext_f[r][0][(x & 0xf)];
            uint8_t t = mul<uint8_t>(l0[inv_shift_map[r]], y);
            et.i_tables[r][x] = en.int_f[r][1][(t >> 4) & 0xf] << 4 | en.int_f[r][0][(t & 0xf)];
        }
    }

    for (n = 0; n < 16; n++) {
        memcpy(u32_temp, et.ty_boxes[0][n], 1024);
        for (x = 0; x < 256; x++) {
            uint8_t  y = en.inv_int_outf[14][shift_map[n]*2][(x >> 4) & 0xf] << 4 | en.inv_int_outf[14][shift_map[n]*2+1][x & 0xf];
            uint32_t t = u32_temp[mul<uint8_t>(NTL::inv(l0[n]), (uint8_t)y)];
            et.ty_boxes[0][n][x] = (
                en.int_s[0][n][0][(t >> 28) & 0xf] << 28 | en.int_s[0][n][1][(t >> 24) & 0xf] << 24 |
                en.int_s[0][n][2][(t >> 20) & 0xf] << 20 | en.int_s[0][n][3][(t >> 16) & 0xf] << 16 |
                en.int_s[0][n][4][(t >> 12) & 0xf] << 12 | en.int_s[0][n][5][(t >>  8) & 0xf] <<  8 |
                en.int_s[0][n][6][(t >>  4) & 0xf] <<  4 | en.int_s[0][n][7][(t      ) & 0xf]   
                // t
            );
        }
    }

    for (r = 1; r < 9; r++) {
        for (n = 0; n < 16; n++) {
            uint8_t entry = shift_map[n];
            memcpy(u32_temp, et.ty_boxes[r][n], 1024);
            for (x = 0; x < 256; x++) {
                uint8_t y = en.inv_int_outm[r-1][8+(entry/4)][2*(entry%4)][(x >> 4) & 0xf] << 4 | en.inv_int_outm[r-1][8+(entry/4)][2*(entry%4)+1][x & 0xf];
                uint32_t t = u32_temp[mul<uint8_t>(NTL::inv(l[r-1][n]), (uint8_t)y)];
                et.ty_boxes[r][n][x] = (
                    en.int_s[r][n][0][(t >> 28) & 0xf] << 28 | en.int_s[r][n][1][(t >> 24) & 0xf] << 24 |
                    en.int_s[r][n][2][(t >> 20) & 0xf] << 20 | en.int_s[r][n][3][(t >> 16) & 0xf] << 16 |
                    en.int_s[r][n][4][(t >> 12) & 0xf] << 12 | en.int_s[r][n][5][(t >>  8) & 0xf] <<  8 |
                    en.int_s[r][n][6][(t >>  4) & 0xf] <<  4 | en.int_s[r][n][7][(t      ) & 0xf]       
                );
                // uint32_t t = u32_temp[mul<uint8_t>(NTL::inv(l[r-1][n]), (uint8_t)x)];
                // et.ty_boxes[r][n][x] = t;
            }
        }
    }

    /*
        Final Round
    */
    for (n = 0; n < 16; n++) {
        memcpy(u8_temp, et.last_box[n], 256);
        for (x = 0; x < 256; x++) {
            et.last_box[n][x] = u8_temp[mul<uint8_t>(NTL::inv(l[8][n]), (uint8_t)x)];
        }
    }
}

void gen_encryption_table(WBAES_ENCRYPTION_TABLE &et, WBAES_NONLINEAR_ENCODING &en, uint32_t *roundkeys) {
    uint8_t    t_boxes[10][16][256];
    uint32_t tyi_table[4][256]     ;

    gen_nonlinear_encoding(en);

    /*
        Generates T-boxes depend on round keys, 
            Tyi-table and complex them. 
    */
    gen_xor_tables(et.s_xor_tables, et.r1_xor_tables, et.r2_xor_tables, et.e_xor_tables, en);
    gen_t_boxes(t_boxes, roundkeys);
    gen_tyi_tables(tyi_table);
    composite_t_tyi(t_boxes, tyi_table, et.ty_boxes, et.last_box);

    /*
        Applies encoding to tables
    */
    apply_encoding(et, en);
}
