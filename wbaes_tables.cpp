/*
    Implementation of Chow's Whitebox AES
        - Generate a encryption table of WBAES-128
*/

#include <iostream>
#include <fstream>

#include "wbaes_tables.h"
#include "gf2_mat.h"

void WBAES_ENCRYPTION_TABLE::read(const char *file) {
    std::ifstream in(file, std::ios::in | std::ios::binary);
    
    if ( in.is_open() ) {
        in.read(reinterpret_cast<char*>(this->xor_tables), sizeof(this->xor_tables));
        in.read(reinterpret_cast<char*>(this->last_box  ), sizeof(this->last_box  ));
        in.read(reinterpret_cast<char*>(this->mbl_tables), sizeof(this->mbl_tables));
        in.read(reinterpret_cast<char*>(this->ty_boxes  ), sizeof(this->ty_boxes  ));
        in.close();
    }
}

void WBAES_ENCRYPTION_TABLE::write(const char *file) {
    std::ofstream out(file, std::ios::out | std::ios::binary);

    if ( out.is_open() ) {
        out.write(reinterpret_cast<char*>(this->xor_tables), sizeof(this->xor_tables));
        out.write(reinterpret_cast<char*>(this->last_box  ), sizeof(this->last_box  ));
        out.write(reinterpret_cast<char*>(this->mbl_tables), sizeof(this->mbl_tables));
        out.write(reinterpret_cast<char*>(this->ty_boxes  ), sizeof(this->ty_boxes  ));
        out.close();

        std::cout << "WBAES-128 Encryption table has been saved." << std::endl;
    }
}

void gen_xor_tables(uint8_t (*xor_tables)[96][16][16]) {
    int r, n, x, y;

    for (r = 0; r < AES_128_ROUND - 1; r++) {
        for (n = 0; n < 96; n++) {
            for (x = 0; x < 16; x++) {
                for (y = 0; y < 16; y++) {
                    xor_tables[r][n][x][y] = x ^ y;
                }
            }
        }
    }
}

void gen_t_boxes(uint8_t (*t_boxes)[16][256], uint8_t *roundkeys) {
    int r, x, n;

    for (r = 0; r < AES_128_ROUND; r++) {
        for (x = 0; x < 256; x++) {
            for (n = 0; n < 16; n++) {
                t_boxes[r][n][x] = sbox[ x ^ roundkeys[r*16+n] ];
                // t_boxes[r][n][x] = sbox[ x ^ shift_map[roundkeys[r*16+n]] ];
            }
        }
    }
    
    for (x = 0; x < 256; x++) {
            for (n = 0; n < 16; n++) {
                t_boxes[9][n][x] ^= shift_map[roundkeys[160+n]];
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

void composite_t_tyi(uint8_t t_boxes[][16][256], uint32_t tyi_tables[][256], uint32_t ty_boxes[][16][256], uint8_t last_box[][256]) {
    int r, n, x, i;

    /* Round-1-9 */
    for (r = 0; r < AES_128_ROUND-1; r++) {
        for (x = 0; x < 256; x++) {
            for (n = 0; n < 16; n++) {
                i = n / 4;
                ty_boxes[r][n][x] = (
                    (tyi_tables[0][t_boxes[r][i][x]] << 24) & 0xff000000 |
                    (tyi_tables[1][t_boxes[r][i][x]] << 16) & 0x00ff0000 |
                    (tyi_tables[2][t_boxes[r][i][x]] <<  8) & 0x0000ff00 |
                    (tyi_tables[3][t_boxes[r][i][x]]      ) & 0x000000ff 
                );
            }
        }
    }

    /* Round-10 */
    memcpy(last_box, t_boxes[9], 16 * 256);
}

void gen_encryption_table(WBAES_ENCRYPTION_TABLE &et, uint8_t *roundkeys) {
    uint8_t  t_boxes[10][16][256];
    uint32_t tyi_table[4][256];
    NTL::mat_GF2 mb[9][4], l[9][16];
    
    /*
        Generate T-boxes depend on round keys, 
            Tyi-table and complex them. 
    */
    gen_xor_tables(et.xor_tables);
    gen_t_boxes(t_boxes, roundkeys);
    gen_tyi_tables(tyi_table);
    composite_t_tyi(t_boxes, tyi_table, et.ty_boxes, et.last_box);
    
    /*
        Generate linear encoding in GF2
            - (MB) Inverible 32x32 matrix
            - (L)  Inverible 8x8 matrix
    */
    int r, n, x;

    for (r = 0; r < 9; r++) {
        /* 32x32 Maxtrix */
        mb[r][0] = gen_gf2_rand_invertible_matrix(32);
        mb[r][1] = gen_gf2_rand_invertible_matrix(32);
        mb[r][2] = gen_gf2_rand_invertible_matrix(32);
        mb[r][3] = gen_gf2_rand_invertible_matrix(32);

        /* 8x8 Matrix */
        for (n = 0; n < 16; n++) {
            l[r][n] = gen_gf2_rand_invertible_matrix(8);
        }
    }

    /*
        Apply 32x32 MB
    */
    for (r = 0; r < 9; r++) {
        for (x = 0; x < 256; x++) {
            for (n = 0; n < 16; n++) {
                et.ty_boxes[r][n][x] = mat_GF2_times_vec_GF2( mb[r][n>>2], et.ty_boxes[r][n][x] );
                et.mbl_tables[r][n][x] = mat_GF2_times_vec_GF2( NTL::inv(mb[r][n>>2]), (uint32_t)(x << (24 - (8 * (n % 4)))) );
            }
        }
    }

    /* 
        Apply 8x8 L
    */
    uint8_t   uint8_temp[256];
    uint32_t uint32_temp[256];

    for (r = 1; r < 9; r++) {
        for (n = 0; n < 16; n++) {
            memcpy(uint32_temp, et.ty_boxes[r][n], 256);
            for (x = 0; x < 256; x++) {
                et.ty_boxes[r][n][x] = uint32_temp[mat_GF2_times_vec_GF2( NTL::inv(l[r-1][n]), (uint8_t)x )];
            }
        }
    }


    for (r = 0; r < 9; r++) {
        for (n = 0; n < 4; n++) {
            for (x = 0; x < 256; x++) {
                uint32_t a = et.mbl_tables[r][n*4  ][x], 
                         b = et.mbl_tables[r][n*4+1][x], 
                         c = et.mbl_tables[r][n*4+2][x], 
                         d = et.mbl_tables[r][n*4+3][x];

                et.mbl_tables[r][n*4  ][x] = mat_GF2_times_vec_GF2(l[r][inv_shift_map[n*4  ]], (uint8_t)(a >> 24)) << 24 |
                                             mat_GF2_times_vec_GF2(l[r][inv_shift_map[n*4+1]], (uint8_t)(a >> 16)) << 16 |
                                             mat_GF2_times_vec_GF2(l[r][inv_shift_map[n*4+2]], (uint8_t)(a >>  8)) <<  8 |
                                             mat_GF2_times_vec_GF2(l[r][inv_shift_map[n*4+3]], (uint8_t)(a      ))       ;

                et.mbl_tables[r][n*4+1][x] = mat_GF2_times_vec_GF2(l[r][inv_shift_map[n*4  ]], (uint8_t)(b >> 24)) << 24 |
                                             mat_GF2_times_vec_GF2(l[r][inv_shift_map[n*4+1]], (uint8_t)(b >> 16)) << 16 |
                                             mat_GF2_times_vec_GF2(l[r][inv_shift_map[n*4+2]], (uint8_t)(b >>  8)) <<  8 |
                                             mat_GF2_times_vec_GF2(l[r][inv_shift_map[n*4+3]], (uint8_t)(b      ))       ;

                et.mbl_tables[r][n*4+2][x] = mat_GF2_times_vec_GF2(l[r][inv_shift_map[n*4  ]], (uint8_t)(c >> 24)) << 24 |
                                             mat_GF2_times_vec_GF2(l[r][inv_shift_map[n*4+1]], (uint8_t)(c >> 16)) << 16 |
                                             mat_GF2_times_vec_GF2(l[r][inv_shift_map[n*4+2]], (uint8_t)(c >>  8)) <<  8 |
                                             mat_GF2_times_vec_GF2(l[r][inv_shift_map[n*4+3]], (uint8_t)(c      ))       ;
                                        
                et.mbl_tables[r][n*4+3][x] = mat_GF2_times_vec_GF2(l[r][inv_shift_map[n*4  ]], (uint8_t)(d >> 24)) << 24 |
                                             mat_GF2_times_vec_GF2(l[r][inv_shift_map[n*4+1]], (uint8_t)(d >> 16)) << 16 |
                                             mat_GF2_times_vec_GF2(l[r][inv_shift_map[n*4+2]], (uint8_t)(d >>  8)) <<  8 |
                                             mat_GF2_times_vec_GF2(l[r][inv_shift_map[n*4+3]], (uint8_t)(d      ))       ;
            }
        }
    }

    for (n = 0; n < 16; n++) {
        memcpy(uint8_temp, et.last_box[n], 256);
        for (x = 0; x < 256; x++) {
            et.last_box[n][x] = uint8_temp[mat_GF2_times_vec_GF2( NTL::inv(l[AES_128_ROUND-2][n]), (uint8_t)x )];
        }
    }
}
