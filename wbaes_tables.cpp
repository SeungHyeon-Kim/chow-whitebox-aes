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

void encode_ext_x(uint8_t (*f)[8][16], uint8_t *x) {
    int i, j;

    for (i = 0; i < 16; i++) {
        x[i] = f[i>>2][(j+1)%8][(x[i] >> 4) & 0xf] << 4 | f[i>>2][j%8][x[i] & 0xf];
    }
}

void decode_ext_x(uint8_t (*inv_f)[8][16], uint8_t *x) {
    int i, j = 0;

    for (i = 0; i < 16; i++) {
        x[i] = inv_f[i>>2][(j+1)%8][(x[i] >> 4) & 0xf] << 4 | inv_f[i>>2][j%8][x[i] & 0xf];
        j += 2;
    }
}

void gen_nonlinear_encoding(WBAES_NONLINEAR_ENCODING &en) {
    int i, j, k, n;

    /*
        External Encoding
    */
    for (i = 0; i < 4; i++) {
        for (j = 0; j < 8; j++) {
            gen_rand(en.ext_f[i][j], en.inv_ext_f[i][j]);
        }
    }

    /*
        Internal Encoding - I
         before start round
    */
    // for (i = 0; i < 16; i++) {
    //     for (j = 0; j < 4; j++) {
    //         for (k = 0; k < 8; k++) {
    //             gen_rand(en.int_f[i][j][k], en.inv_int_f[i][j][k]);
    //         }
    //     }
    // }

    /*
        Internal Encoding - II
         ty_boxes
         round 1 ~ 9
    */
    for (j = 0; j < 16; j++) {
        memcpy(en.int_g[0][j]    , en.inv_ext_f, 16);
        memcpy(en.inv_int_g[0][j], en.ext_f    , 16);
    }
    
    for (i = 1; i < 9; i++) {
        for (j = 0; j < 16; j++) {
            for (k = 0; k < 8; k++) {
                gen_rand(en.int_g[i][j][k], en.inv_int_g[i][j][k]);
            }
        }
    }

    /*
        Internal Encoding - III
         mbl_tables
         round 1 ~ 9
    */
    for (i = 0; i < 9; i++) {
        for (j = 0; j < 16; j++) {
            for (k = 0; k < 4; k++) {
                gen_rand(en.int_h[i][j][k], en.inv_int_h[i][j][k]);
            }
        }
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

void gen_xor_tables(uint8_t (*i_xor_tables)[16][16], uint8_t (*xor_tables)[96][16][16]) {
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

    for (n = 0; n < 960; n++) {
        for (x = 0; x < 16; x++) {
            for (y = 0; y < 16; y++) {
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
    for (r = 0; r < 16; r++) {
        l0[r] = gen_gf2_rand_invertible_matrix(8);
        for (x = 0; x < 256; x++) {
            et.ia_table[r][x] = mul<uint8_t>(l0[r], (uint8_t)(et.ia_table[r][x]));
        }
    }

    for (n = 0; n < 16; n++) {
        memcpy(u32_temp, et.ty_boxes[0][n], 1024);
        for (x = 0; x < 256; x++) {
            et.ty_boxes[0][n][x] = u32_temp[mul<uint8_t>(NTL::inv(l0[shift_map[n]]), (uint8_t)x)];
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
    gen_xor_tables(et.i_xor_tables, et.xor_tables);
    gen_t_boxes(t_boxes, roundkeys, en);
    gen_tyi_tables(tyi_table);
    composite_t_tyi(t_boxes, tyi_table, et.ty_boxes, et.last_box);

    /*
        Applies encoding to tables
    */
    apply_encoding(et, en);
}
