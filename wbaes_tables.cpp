/*
    Implementation of Chow's Whitebox AES
        - Generate a encryption table of WBAES-128
*/

#include <iostream>
#include <cstdlib>
#include <NTL/mat_GF2.h>

#include "gf.h"
#include "wbaes_tables.h"

extern uint8_t         Sbox[256];
extern uint8_t     shift_map[16];
extern uint8_t inv_shift_map[16];

/*
    Operations on GF(2) using NTL
*/
static NTL::mat_GF2 gen_gf2_rand_matrix(const int dim) {
    int i, j;
    NTL::mat_GF2 ret(NTL::INIT_SIZE, dim, dim);
    
    for (i = 0; i < dim; i++) {
        for (j = 0; j < dim; j++) {
            ret[i][j] = NTL::random_GF2();
        }
    }

    return ret;
}

static NTL::mat_GF2 gen_gf2_rand_invertible_matrix(const int dim) {
    for (;;) {
        NTL::mat_GF2 ret = gen_gf2_rand_matrix(dim);
        if (NTL::determinant(ret) != 0) {
            return ret;
        }
    }
}

template <typename T>
static inline NTL::vec_GF2 scalar2vec(const T in) {
    int i, bit_len = sizeof(T) * 8;
    NTL::vec_GF2 ret;

    ret.SetLength(bit_len);
    
    for (i = 0; i < bit_len; i++) {
        ret[bit_len - 1 - i] = ((in >> i) & 0x1);
    }
    
    return ret;
}

template <typename T>
static inline T vec2scalar(const NTL::vec_GF2& in) {
  int i, bit_len = sizeof(T) * 8;
  T ret = 0;
  
  for (i = 0; i < bit_len; i++) {
    ret = (ret << 1) | NTL::rep(in[i]);
  }

  return ret;
}

template <typename T>
static inline T mul(const NTL::mat_GF2& mat, const T x) {
  return vec2scalar<T>(mat * scalar2vec<T>(x));
}

/*
    Generates random encoding
*/
static void knuth_shuffle(uint8_t *x) {
    int i, j;
    uint8_t temp;

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

static void gen_nonlinear_encoding(WBAES_EXT_ENCODING &ee, WBAES_INT_ENCODING &ie) {
    int i, j, k;

    /*
        External Encoding
    */
    for (i = 0; i < 16; i++) {
        for (j = 0; j < 2; j++) {
            gen_rand(ee.ext_f[i][j], ee.inv_ext_f[i][j]);
            gen_rand(ee.ext_g[i][j], ee.inv_ext_g[i][j]);
        }
    }

    /*
        Internal Encoding (IA, XOR-128 x 15)
         - IA   16 x 2 x 16
         - XOR  15 x 32 x 16
    */
    // for (i = 0; i < 16; i++) {      // encoding for the output of IA-tables
    //     for (j = 0; j < 2; j++) {
    //         gen_rand(ie.int_f[i][j], ie.inv_int_f[i][j]);
    //     }
    // }

    // for (i = 0; i < 8; i++) {
    //     for (j = 0; j < 16; j++) {
    //         k = i << 1;
    //         n = j << 1;

    //         memcpy(ie.int_xf[i][n], ie.inv_int_f[k  ][1], 16); memcpy(ie.int_xf[i][n+1], ie.inv_int_f[k  ][0], 16);
    //         memcpy(ie.int_yf[i][n], ie.inv_int_f[k+1][1], 16); memcpy(ie.int_yf[i][n+1], ie.inv_int_f[k+1][0], 16);
    //     }
    // }

    // for (i = 0; i < 15; i++) {      // encoding for the output of xor-tables
    //     for (j = 0; j < 32; j++) {
    //         gen_rand(ie.int_outf[i][j], ie.inv_int_outf[i][j]);
    //     }
    // }
    // memcpy(ie.int_xf[ 8], ie.inv_int_outf[ 0], 512); memcpy(ie.int_yf[ 8], ie.inv_int_outf[ 1], 512);
    // memcpy(ie.int_xf[ 9], ie.inv_int_outf[ 2], 512); memcpy(ie.int_yf[ 9], ie.inv_int_outf[ 3], 512);
    // memcpy(ie.int_xf[10], ie.inv_int_outf[ 4], 512); memcpy(ie.int_yf[10], ie.inv_int_outf[ 5], 512);
    // memcpy(ie.int_xf[11], ie.inv_int_outf[ 6], 512); memcpy(ie.int_yf[11], ie.inv_int_outf[ 7], 512);
    // memcpy(ie.int_xf[12], ie.inv_int_outf[ 8], 512); memcpy(ie.int_yf[12], ie.inv_int_outf[ 9], 512);
    // memcpy(ie.int_xf[13], ie.inv_int_outf[10], 512); memcpy(ie.int_yf[13], ie.inv_int_outf[11], 512);
    // memcpy(ie.int_xf[14], ie.inv_int_outf[12], 512); memcpy(ie.int_yf[14], ie.inv_int_outf[13], 512);

    /*
        Internal Encoding - I
         - Ty-Boxes  9 x 16 x 8 x 16
         - XOR
    */
    for (i = 0; i < 9; i++) {       // encoding for the output of ty-boxes
        for (j = 0; j < 16; j++) {
            for (k = 0; k < 8; k++) {
                gen_rand(ie.int_s[i][j][k], ie.inv_int_s[i][j][k]);
            }
        }
    }

    for (i = 0; i < 9; i++) {
        for (j = 0; j < 8; j++) {
            memcpy(ie.int_xs[i][j], ie.inv_int_s[i][j*2  ], 128);
            memcpy(ie.int_ys[i][j], ie.inv_int_s[i][j*2+1], 128);
        }
    }

    for (i = 0; i < 9; i++) {       // encoding for the output of xor-tables
        for (j = 0; j < 12; j++) {
            for (k = 0; k < 8; k++) {
                gen_rand(ie.int_outs[i][j][k], ie.inv_int_outs[i][j][k]);
            }
        }
    }

    for (i = 0; i < 9; i++) {
        memcpy(ie.int_xs[i][ 8], ie.inv_int_outs[i][0], 128); memcpy(ie.int_ys[i][ 8], ie.inv_int_outs[i][1], 128);
        memcpy(ie.int_xs[i][ 9], ie.inv_int_outs[i][2], 128); memcpy(ie.int_ys[i][ 9], ie.inv_int_outs[i][3], 128);
        memcpy(ie.int_xs[i][10], ie.inv_int_outs[i][4], 128); memcpy(ie.int_ys[i][10], ie.inv_int_outs[i][5], 128);
        memcpy(ie.int_xs[i][11], ie.inv_int_outs[i][6], 128); memcpy(ie.int_ys[i][11], ie.inv_int_outs[i][7], 128);
    }

    /*
        Internal Encoding - II
         - MBL-tables  9 x 16 x 8 x 16
         - XOR
    */
    for (i = 0; i < 9; i++) {       // encoding for the output of mbl-tables
        for (j = 0; j < 16; j++) {
            for (k = 0; k < 8; k++) {
                gen_rand(ie.int_m[i][j][k], ie.inv_int_m[i][j][k]);
            }
        }
    }

    for (i = 0; i < 9; i++) {
        for (j = 0; j < 8; j++) {
            memcpy(ie.int_xm[i][j], ie.inv_int_m[i][j*2  ], 128);
            memcpy(ie.int_ym[i][j], ie.inv_int_m[i][j*2+1], 128);
        }
    }

    for (i = 0; i < 9; i++) {       // encoding for the output of xor-tables
        for (j = 0; j < 12; j++) {
            for (k = 0; k < 8; k++) {
                gen_rand(ie.int_outm[i][j][k], ie.inv_int_outm[i][j][k]);
            }
        }
    }

    for (i = 0; i < 9; i++) {
        memcpy(ie.int_xm[i][ 8], ie.inv_int_outm[i][0], 128); memcpy(ie.int_ym[i][ 8], ie.inv_int_outm[i][1], 128);
        memcpy(ie.int_xm[i][ 9], ie.inv_int_outm[i][2], 128); memcpy(ie.int_ym[i][ 9], ie.inv_int_outm[i][3], 128);
        memcpy(ie.int_xm[i][10], ie.inv_int_outm[i][4], 128); memcpy(ie.int_ym[i][10], ie.inv_int_outm[i][5], 128);
        memcpy(ie.int_xm[i][11], ie.inv_int_outm[i][6], 128); memcpy(ie.int_ym[i][11], ie.inv_int_outm[i][7], 128);
    }

    /*
        Interal Encoding (IA, XOR-128)
    */
    // for (i = 0; i < 16; i++) {
    //     for (j = 0; j < 2; j++) {
    //         gen_rand(ie.int_o[i][j], ie.inv_int_o[i][j]);
    //     }
    // }

    // for (i = 0; i < 8; i++) {
    //     for (j = 0; j < 16; j++) {
    //         k = i << 1;
    //         n = j << 1;

    //         memcpy(ie.int_xo[i][n], ie.inv_int_o[k  ][1], 16); memcpy(ie.int_xo[i][n+1], ie.inv_int_o[k  ][0], 16);
    //         memcpy(ie.int_yo[i][n], ie.inv_int_o[k+1][1], 16); memcpy(ie.int_yo[i][n+1], ie.inv_int_o[k+1][0], 16);
    //     }
    // }

    // for (i = 0; i < 14; i++) {      // encoding for the output of xor-tables
    //     for (j = 0; j < 32; j++) {
    //         gen_rand(ie.int_outo[i][j], ie.inv_int_outo[i][j]);
    //     }
    // }
    // memcpy(ie.int_xo[ 8], ie.inv_int_outf[ 0], 512); memcpy(ie.int_yo[ 8], ie.inv_int_outf[ 1], 512);
    // memcpy(ie.int_xo[ 9], ie.inv_int_outf[ 2], 512); memcpy(ie.int_yo[ 9], ie.inv_int_outf[ 3], 512);
    // memcpy(ie.int_xo[10], ie.inv_int_outf[ 4], 512); memcpy(ie.int_yo[10], ie.inv_int_outf[ 5], 512);
    // memcpy(ie.int_xo[11], ie.inv_int_outf[ 6], 512); memcpy(ie.int_yo[11], ie.inv_int_outf[ 7], 512);
    // memcpy(ie.int_xo[12], ie.inv_int_outf[ 8], 512); memcpy(ie.int_yo[12], ie.inv_int_outf[ 9], 512);
    // memcpy(ie.int_xo[13], ie.inv_int_outf[10], 512); memcpy(ie.int_yo[13], ie.inv_int_outf[11], 512);
    // memcpy(ie.int_xo[14], ie.inv_int_outf[12], 512); memcpy(ie.int_yo[14], ie.inv_int_outf[13], 512);
    
    // for (i = 0; i < 16; i++) {
    //     memcpy(ie.int_outo[15][i*2  ], ee.inv_ext_g[i][1], 16); memcpy(ie.inv_int_outo[15][i*2  ], ee.ext_g[i][1], 16);
    //     memcpy(ie.int_outo[15][i*2+1], ee.inv_ext_g[i][0], 16); memcpy(ie.inv_int_outo[15][i*2+1], ee.ext_g[i][0], 16);
    // }
}

static void gen_xor_tables(uint8_t (*r1_xor_tables)[96][16][16], uint8_t (*r2_xor_tables)[96][16][16], const WBAES_EXT_ENCODING &ee, const WBAES_INT_ENCODING &ie) {
    /*
        xor_tables
          |01 02| |03 04| |05 06| |07 08| |09 10| |11 12| |13 14| |15 16|
             |       |       |       |       |       |       |       |
             1       2       3       4       5       6       7       8
              \     /         \     /         \     /         \     / 
                 9               10              11              12
    */    
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
                    r1_xor_tables[r][n][x][y] = ie.int_outs[r][i][j][ie.int_xs[r][i][j][x] ^ ie.int_ys[r][i][j][y]];
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
                    r2_xor_tables[r][n][x][y] = ie.int_outm[r][i][j][ie.int_xm[r][i][j][x] ^ ie.int_ym[r][i][j][y]];
                }
            }
        }
    }
    
    /*
        IA type - 1 -> XOR-128
    */
    // for (n = 0; n < 480; n++) {
    //     int i = n >> 5;     // 0 1 ... 14
    //     int j = n % 32;     // 0 1 ... 31

    //     for (x = 0; x < 16; x++) {
    //         for (y = 0; y < 16; y++) {
    //             s_xor_tables[n][x][y] = ie.int_outf[i][j][(ie.int_xf[i][j][x]) ^ (ie.int_yf[i][j][y])];
    //         }
    //     }
    // }

    /*
        IA type - 2 -> XOR-128
    */
    // for (n = 0; n < 480; n++) {
    //     int i = n >> 5;     // 0 1 ... 14
    //     int j = n % 32;     // 0 1 ... 31

    //     for (x = 0; x < 16; x++) {
    //         for (y = 0; y < 16; y++) {
    //             e_xor_tables[n][x][y] = ie.int_outo[i][j][(ie.int_xo[i][j][x]) ^ (ie.int_yo[i][j][y])];
    //         }
    //     }
    // }
}

static void gen_t_boxes(uint8_t (*t_boxes)[16][256], uint32_t *roundkeys) {
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

static void gen_tyi_tables(uint32_t (*tyi_tables)[256]) {
    int x;

    for (x = 0; x < 256; x++) {
        tyi_tables[0][x] = (gf_mul(2, x) << 24) |           (x  << 16) |           (x  << 8) | gf_mul(3, x);
        tyi_tables[1][x] = (gf_mul(3, x) << 24) | (gf_mul(2, x) << 16) |           (x  << 8) |          (x);
        tyi_tables[2][x] =           (x  << 24) | (gf_mul(3, x) << 16) | (gf_mul(2, x) << 8) |          (x);
        tyi_tables[3][x] =           (x  << 24) |           (x  << 16) | (gf_mul(3, x) << 8) | gf_mul(2, x);
    }
}

static void composite_t_tyi(uint8_t (*t_boxes)[16][256], uint32_t (*tyi_tables)[256], uint32_t (*ty_boxes)[16][256], uint8_t (*last_box)[256]) {
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

static void apply_encoding(WBAES_ENCRYPTION_TABLE &et, WBAES_EXT_ENCODING &ee, WBAES_INT_ENCODING &ie) {
    uint8_t   u8_temp[256];
    uint32_t u32_temp[256];
    NTL::mat_GF2 mb[9][4], l[10][16], l0[16], cl0;

    int r, n, x;

    /*
        Linear Encoding
         - (MB) Inverible 32x32 matrix
         - (L)  Inverible 8x8 matrix
    */
    uint8_t  y, t1, t2, t3, t4;
    uint32_t t;

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
                
                uint8_t y = ie.inv_int_outs[r][8+(n/4)][(n%4)*2][(x >> 4) & 0xf] << 4 | ie.inv_int_outs[r][8+(n/4)][(n%4)*2+1][x & 0xf];
                et.mbl_tables[r][n][x] = mul<uint32_t>(NTL::inv(mb[r][n/4]), (uint32_t)(y << (24 - (8 * (n % 4)))));
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
        
        for (n = 0; n < 16; n++) {
            for (x = 0; x < 256; x++) {
                t1 = mul<uint8_t>(l[r][inv_shift_map[(4*(n/4))  ]], (uint8_t)(et.mbl_tables[r][n][x] >> 24));
                t2 = mul<uint8_t>(l[r][inv_shift_map[(4*(n/4))+1]], (uint8_t)(et.mbl_tables[r][n][x] >> 16));
                t3 = mul<uint8_t>(l[r][inv_shift_map[(4*(n/4))+2]], (uint8_t)(et.mbl_tables[r][n][x] >>  8));
                t4 = mul<uint8_t>(l[r][inv_shift_map[(4*(n/4))+3]], (uint8_t)(et.mbl_tables[r][n][x]      ));

                et.mbl_tables[r][n][x] = (
                    ie.int_m[r][n][0][(t1 >> 4) & 0xf] << 28 | ie.int_m[r][n][1][t1 & 0xf] << 24 |
                    ie.int_m[r][n][2][(t2 >> 4) & 0xf] << 20 | ie.int_m[r][n][3][t2 & 0xf] << 16 |
                    ie.int_m[r][n][4][(t3 >> 4) & 0xf] << 12 | ie.int_m[r][n][5][t3 & 0xf] <<  8 |
                    ie.int_m[r][n][6][(t4 >> 4) & 0xf] <<  4 | ie.int_m[r][n][7][t4 & 0xf]
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

    // for (r = 0; r < 16; r++) {
    //     for (x = 0; x < 256; x++) {
    //         y = ee.inv_ext_f[r][1][(x >> 4) & 0xf] << 4 | ee.inv_ext_f[r][0][(x & 0xf)];
    //         t = mul<uint8_t>(l0[inv_shift_map[r]], y);
    //         et.i_tables[r][r][x] = ie.int_f[r][1][(t >> 4) & 0xf] << 4 | ie.int_f[r][0][(t & 0xf)];
    //     }
    // }

    for (n = 0; n < 16; n++) {
        memcpy(u32_temp, et.ty_boxes[0][n], 1024);
        for (x = 0; x < 256; x++) {
            y = ee.inv_ext_f[shift_map[n]][1][(x >> 4) & 0xf] << 4 | ee.inv_ext_f[shift_map[n]][0][x & 0xf];
            // y = ie.inv_int_outf[14][shift_map[n]*2][(x >> 4) & 0xf] << 4 | ie.inv_int_outf[14][shift_map[n]*2+1][x & 0xf];
            t = u32_temp[(uint8_t)y];
            // t = u32_temp[mul<uint8_t>(NTL::inv(l0[n]), (uint8_t)y)];
            et.ty_boxes[0][n][x] = (
                ie.int_s[0][n][0][(t >> 28) & 0xf] << 28 | ie.int_s[0][n][1][(t >> 24) & 0xf] << 24 |
                ie.int_s[0][n][2][(t >> 20) & 0xf] << 20 | ie.int_s[0][n][3][(t >> 16) & 0xf] << 16 |
                ie.int_s[0][n][4][(t >> 12) & 0xf] << 12 | ie.int_s[0][n][5][(t >>  8) & 0xf] <<  8 |
                ie.int_s[0][n][6][(t >>  4) & 0xf] <<  4 | ie.int_s[0][n][7][(t      ) & 0xf]   
            );
        }
    }

    for (r = 1; r < 9; r++) {
        for (n = 0; n < 16; n++) {
            uint8_t entry = shift_map[n];
            memcpy(u32_temp, et.ty_boxes[r][n], 1024);
            for (x = 0; x < 256; x++) {
                y = ie.inv_int_outm[r-1][8+(entry/4)][2*(entry%4)][(x >> 4) & 0xf] << 4 | ie.inv_int_outm[r-1][8+(entry/4)][2*(entry%4)+1][x & 0xf];
                t = u32_temp[mul<uint8_t>(NTL::inv(l[r-1][n]), (uint8_t)y)];
                et.ty_boxes[r][n][x] = (
                    ie.int_s[r][n][0][(t >> 28) & 0xf] << 28 | ie.int_s[r][n][1][(t >> 24) & 0xf] << 24 |
                    ie.int_s[r][n][2][(t >> 20) & 0xf] << 20 | ie.int_s[r][n][3][(t >> 16) & 0xf] << 16 |
                    ie.int_s[r][n][4][(t >> 12) & 0xf] << 12 | ie.int_s[r][n][5][(t >>  8) & 0xf] <<  8 |
                    ie.int_s[r][n][6][(t >>  4) & 0xf] <<  4 | ie.int_s[r][n][7][(t      ) & 0xf]       
                );
            }
        }
    }

    /*
        Final Round
    */
    for (n = 0; n < 16; n++) {
        uint8_t entry = shift_map[n];
        memcpy(u8_temp, et.last_box[n], 256);
        for (x = 0; x < 256; x++) {
            y = ie.inv_int_outm[8][8+(entry/4)][2*(entry%4)][(x >> 4) & 0xf] << 4 | ie.inv_int_outm[8][8+(entry/4)][2*(entry%4)+1][x & 0xf];
            t = u8_temp[mul<uint8_t>(NTL::inv(l[8][n]), (uint8_t)y)];
            et.last_box[n][x] = ee.inv_ext_g[n][1][(t >> 4) & 0xf] << 4 | ee.inv_ext_g[n][0][t & 0xf];
        }
    }
}

void wbaes_gen_encryption_table(WBAES_ENCRYPTION_TABLE &et, WBAES_EXT_ENCODING &ee, WBAES_INT_ENCODING &ie, uint32_t *roundkeys) {
    uint8_t    t_boxes[10][16][256];
    uint32_t tyi_table[4][256]     ;

    /*
        Generates Non-linear random encoding table
            External Encoding - ee
            Internal Encoding - ie
    */
    gen_nonlinear_encoding(ee, ie);

    /*
        Generates T-boxes depend on round keys, 
            Tyi-table and complex them. 
    */
    gen_t_boxes(t_boxes, roundkeys);
    gen_tyi_tables(tyi_table);
    composite_t_tyi(t_boxes, tyi_table, et.ty_boxes, et.last_box);

    /*
        Applies encoding to tables
    */
    apply_encoding(et, ee, ie);
    gen_xor_tables(et.r1_xor_tables, et.r2_xor_tables, ee, ie);
}
