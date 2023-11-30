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

    std::srand(std::time(nullptr));

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

void inv_shift_rows(uint8_t *x) {
    int i;
    uint8_t temp[16];

    memcpy(temp, x, 16);

    for (i = 0; i < 16; i++) {
        x[i] = temp[inv_shift_map[i]];
    }
}

void add_rk(uint8_t *x, uint32_t *rk) {
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
         - IA type   16 x 16 x 2 x 16
         - XOR table 15 x 32 x 16
    */
    for (i = 0; i < 16; i++) {      // encoding for the output of IA-tables
        for (j = 0; j < 16; j++) {
            for (k = 0; k < 2; k++) {
                gen_rand(en.int_f[i][j][k], en.inv_int_f[i][j][k]);
            }
        }
    }

    for (i = 0; i < 15; i++) {      // encoding for the output of xor-tables
        for (j = 0; j < 32; j++) {
            gen_rand(en.int_outf[i][j], en.inv_int_outf[i][j]);
        }
    }

    for (i = 0; i < 8; i++) {
        for (j = 0; j < 16; j++) {
            memcpy(en.int_xf[i][(j<<1)], en.inv_int_f[(i<<1)  ][j][1], 16); memcpy(en.int_xf[i][(j<<1)+1], en.inv_int_f[(i<<1)  ][j][0], 16);
            memcpy(en.int_yf[i][(j<<1)], en.inv_int_f[(i<<1)+1][j][1], 16); memcpy(en.int_yf[i][(j<<1)+1], en.inv_int_f[(i<<1)+1][j][0], 16);
        }
    }
    for (j = 0; j < 32; j++) {
        memcpy(en.int_xf[ 8][j], en.inv_int_outf[ 0][j], 16); memcpy(en.int_yf[ 8][j], en.inv_int_outf[ 1][j], 16);     // 8th xor
        memcpy(en.int_xf[ 9][j], en.inv_int_outf[ 2][j], 16); memcpy(en.int_yf[ 9][j], en.inv_int_outf[ 3][j], 16);     // 9th
        memcpy(en.int_xf[10][j], en.inv_int_outf[ 4][j], 16); memcpy(en.int_yf[10][j], en.inv_int_outf[ 5][j], 16);     // ...
        memcpy(en.int_xf[11][j], en.inv_int_outf[ 6][j], 16); memcpy(en.int_yf[11][j], en.inv_int_outf[ 7][j], 16);
        memcpy(en.int_xf[12][j], en.inv_int_outf[ 8][j], 16); memcpy(en.int_yf[12][j], en.inv_int_outf[ 9][j], 16);
        memcpy(en.int_xf[13][j], en.inv_int_outf[10][j], 16); memcpy(en.int_yf[13][j], en.inv_int_outf[11][j], 16);
        memcpy(en.int_xf[14][j], en.inv_int_outf[12][j], 16); memcpy(en.int_yf[14][j], en.inv_int_outf[13][j], 16);     // 14th
    }

    /*
        Internal Encoding - II
         ty_boxes
         round 1 ~ 9
    */
    // for (j = 0; j < 16; j++) {
    //     memcpy(en.int_g[0][j]    , en.inv_ext_f, 16);
    //     memcpy(en.inv_int_g[0][j], en.ext_f    , 16);
    // }
    
    // for (i = 1; i < 9; i++) {
    //     for (j = 0; j < 16; j++) {
    //         for (k = 0; k < 8; k++) {
    //             gen_rand(en.int_g[i][j][k], en.inv_int_g[i][j][k]);
    //         }
    //     }
    // }

    /*
        Internal Encoding - III
         mbl_tables
         round 1 ~ 9
    */
    // for (i = 0; i < 9; i++) {
    //     for (j = 0; j < 16; j++) {
    //         for (k = 0; k < 4; k++) {
    //             gen_rand(en.int_h[i][j][k], en.inv_int_h[i][j][k]);
    //         }
    //     }
    // }

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

void gen_xor_tables(uint8_t (*i_xor_tables)[16][16], uint8_t (*xor_tables)[96][16][16], const WBAES_NONLINEAR_ENCODING &en) {
    int r, n, x, y;

    for (r = 0; r < 9; r++) {
        for (n = 0; n < 192; n++) {
            for (x = 0; x < 16; x++) {
                for (y = 0; y < 16; y++) {
                    xor_tables[r][n][x][y] = x ^ y;
                }
            }
        }
    }
    
    /*
        IA type -> XOR-128
    */
    for (n = 0; n < 256; n++) {
        int i = n >> 5;
        int j = n % 32;

        // printf("%d, %d\n", i, j);

        for (x = 0; x < 16; x++) {
            for (y = 0; y < 16; y++) {
                i_xor_tables[n][x][y] = x ^ y;
                // i_xor_tables[n][x][y] = en.int_outf[i][j][((en.int_xf[i][j][x]) & 0xf) ^ ((en.int_yf[i][j][y]) & 0xf)] & 0xf;
                // i_xor_tables[n][x][y] = ((en.int_xf[i][j][x]) & 0xf) ^ ((en.int_yf[i][j][y]) & 0xf);
            }
        }
    }

    for (n = 256; n < 480; n++) {   // 448
        for(x = 0; x < 16; x++) {
            for (y = 0; y < 16; y++) {
                // i_xor_tables[n][x][y] = en.int_xf[(n>>5)][(n%32)][x] ^ en.int_yf[(n>>5)][(n%32)][y];
                i_xor_tables[n][x][y] = x ^ y;
            }
        }
    }
}

void gen_t_boxes(uint8_t (*t_boxes)[16][256], uint32_t *roundkeys, WBAES_NONLINEAR_ENCODING &en) {
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

    /* Round-1-9 */
    for (r = 0; r < 9; r++) {
        for (x = 0; x < 256; x++) {
            for (n = 0; n < 16; n++) {
                ty_boxes[r][n][x] = tyi_tables[n%4][t_boxes[r][n][x]];
            }
        }
    }

    /* Round-10 */
    memcpy(last_box, t_boxes[9], 16 * 256);
}

void gen_ia_table(uint8_t (*ia_table)[256]) {
    int n, x;
    for (n = 0; n < 16; n++) {
        for (x = 0; x < 256; x++) {
            ia_table[n][x] = x;
        }
    }
}

void apply_encoding(WBAES_ENCRYPTION_TABLE &et, WBAES_NONLINEAR_ENCODING &en) {
    uint8_t   u8_temp[256];
    uint32_t u32_temp[256];
    NTL::mat_GF2 mb[9][4], l[10][16], l0[16], cl0;

    /*
        Linear Encoding
         - (MB) Inverible 32x32 matrix
         - (L)  Inverible 8x8 matrix
    */
    int r, n, x;

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
                et.mbl_tables[r][n][x] = (
                    mul<uint8_t>(l[r][inv_shift_map[(4*(n/4))  ]], (uint8_t)(et.mbl_tables[r][n][x] >> 24)) << 24 |
                    mul<uint8_t>(l[r][inv_shift_map[(4*(n/4))+1]], (uint8_t)(et.mbl_tables[r][n][x] >> 16)) << 16 |
                    mul<uint8_t>(l[r][inv_shift_map[(4*(n/4))+2]], (uint8_t)(et.mbl_tables[r][n][x] >>  8)) <<  8 |
                    mul<uint8_t>(l[r][inv_shift_map[(4*(n/4))+3]], (uint8_t)(et.mbl_tables[r][n][x]      ))       
                );
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
            et.i_tables[r][x] = t;
            // et.i_tables[r][x] = en.int_f[r][r][1][(t >> 4) & 0xf] << 4 | en.int_f[r][r][0][(t & 0xf)];
        }
    }

    for (n = 0; n < 16; n++) {
        memcpy(u32_temp, et.ty_boxes[0][n], 1024);
        for (x = 0; x < 256; x++) {
            et.ty_boxes[0][n][x] = u32_temp[mul<uint8_t>(NTL::inv(l0[n]), (uint8_t)x)];
        }
    }

    for (r = 1; r < 9; r++) {
        for (n = 0; n < 16; n++) {
            memcpy(u32_temp, et.ty_boxes[r][n], 1024);
            for (x = 0; x < 256; x++) {
                et.ty_boxes[r][n][x] = u32_temp[mul<uint8_t>(NTL::inv(l[r-1][n]), (uint8_t)x)];
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
    uint8_t  t_boxes[10][16][256];
    uint32_t    tyi_table[4][256];

    gen_nonlinear_encoding(en);
    /*
        Generates T-boxes depend on round keys, 
            Tyi-table and complex them. 
    */
    gen_xor_tables(et.i_xor_tables, et.xor_tables, en);
    gen_t_boxes(t_boxes, roundkeys, en);
    gen_tyi_tables(tyi_table);
    composite_t_tyi(t_boxes, tyi_table, et.ty_boxes, et.last_box);

    /*
        Applies encoding to tables
    */
    apply_encoding(et, en);
}
