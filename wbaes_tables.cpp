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
        in.read(reinterpret_cast<char*>(this->mbl_tables), sizeof(this->mbl_tables));
        in.read(reinterpret_cast<char*>(this->ty_boxes  ), sizeof(this->ty_boxes  ));
        in.close();
    }
}

void WBAES_ENCRYPTION_TABLE::write(const char *file) {
    std::ofstream out(file, std::ios::out | std::ios::binary);

    if ( out.is_open() ) {
        out.write(reinterpret_cast<char*>(this->xor_tables), sizeof(this->xor_tables));
        out.write(reinterpret_cast<char*>(this->mbl_tables), sizeof(this->mbl_tables));
        out.write(reinterpret_cast<char*>(this->ty_boxes  ), sizeof(this->ty_boxes  ));
        out.close();

        std::cout << "WBAES-128 Encryption table has been saved." << std::endl;
    }
}

/*
    Constants Variables
*/

constexpr uint8_t sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

constexpr uint8_t shift_map[16] = {
    0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11
};

constexpr uint8_t inv_shift_map[16] = {
    0, 13, 10, 7, 4, 1, 14, 11, 8, 5, 2, 15, 12, 9, 6, 3
};

void gen_xor_tables(uint8_t xor_tables[][96][16][16]) {
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

void gen_t_boxes(uint8_t t_boxes[][16][256], uint8_t *roundkeys) {
    int r, x, n;

    for (r = 0; r < AES_128_ROUND; r++) {
        for (x = 0; x < 256; x++) {
            for (n = 0; n < 16; n++) {
                t_boxes[r][n][x] = sbox[ x ^ shift_map[roundkeys[n]] ];
            }
        }
    }
}

void gen_tyi_tables(uint32_t tyi_tables[][256]) {
    int x;

    for (x = 0; x < 256; x++) {
        tyi_tables[0][x] = (GF_mul(2, x) << 24) |           (x  << 16) |           (x  << 8) | GF_mul(3, x);
        tyi_tables[1][x] = (GF_mul(3, x) << 24) | (GF_mul(2, x) << 16) |           (x  << 8) |          (x);
        tyi_tables[2][x] =           (x  << 24) | (GF_mul(3, x) << 16) | (GF_mul(2, x) << 8) |          (x);
        tyi_tables[3][x] =           (x  << 24) |           (x  << 16) | (GF_mul(3, x) << 8) | GF_mul(2, x);
    }
}

void composite_t_tyi(uint8_t t_boxes[][16][256], uint32_t tyi_tables[][256], uint32_t ty_boxes[][16][256]) {
    int r, n, x, i;

    for (r = 0; r < AES_128_ROUND; r++) {
        for (x = 0; x < 256; x++) {
            for (n = 0; n < 16; n++) {
                i = n / 4;
                ty_boxes[r][n][x] = 
                    (tyi_tables[0][t_boxes[r][i][x]] << 24) & 0xff000000 |
                    (tyi_tables[1][t_boxes[r][i][x]] << 16) & 0x00ff0000 |
                    (tyi_tables[2][t_boxes[r][i][x]] <<  8) & 0x0000ff00 |
                    (tyi_tables[3][t_boxes[r][i][x]]      ) & 0x000000ff ;
            }
        }
    }
}

void gen_encryption_table(WBAES_ENCRYPTION_TABLE &et, uint8_t *roundkeys) {
    uint8_t  t_boxes[10][16][256];
    uint32_t tyi_table[4][256];
    uint32_t ty_boxes[10][16][256], mbl[9][16][256];
    NTL::mat_GF2 mb[9][4], l[9][16];
    
    /*
        Generate T-boxes depend on round keys, 
            Tyi-table and complex them. 
    */
    gen_t_boxes(t_boxes, roundkeys);
    gen_tyi_tables(tyi_table);
    composite_t_tyi(t_boxes, tyi_table, ty_boxes);
    
    /*
        Generate linear encoding in GF2
            - (MB) Inverible 32x32 matrix
            - (L)  Inverible 8x8 matrix
    */
    int r, i, j;

    for (r = 0; r < 9; r++) {
        /* 32x32 Maxtrix */
        mb[r][0] = gen_gf2_rand_invertible_matrix(32);
        mb[r][1] = gen_gf2_rand_invertible_matrix(32);
        mb[r][2] = gen_gf2_rand_invertible_matrix(32);
        mb[r][3] = gen_gf2_rand_invertible_matrix(32);

        /* 8x8 Matrix */
        for (i = 0; i > 16; i++) {
            l[r][i] = gen_gf2_rand_invertible_matrix(8);
        }
    }

    /*
        Apply 32x32 MB
    */
    for (r = 0; r < 9; r++) {
        for (i = 0; i < 256; i++) {
            for (j = 0; j < 16; j++) {
                ty_boxes[r][j][i] = mat_GF2_times_vec_GF2( mb[r][j>>2], ty_boxes[r][j][i] );
                mbl[r][j][i] = mat_GF2_times_vec_GF2( NTL::inv(mb[r][j>>2]), (uint32_t)(i << (24 - (8 * (j % 4)))) );
            }
        }
    }

    /* 
        Apply 8x8 L
    */
    uint32_t temp[256];

    for (r = 1; r < 9; r++) {
        for (i = 0; i < 16; i++) {
            memcpy(temp, ty_boxes[r][i], 1024);
            for (j = 0; j < 256; j++) {
                ty_boxes[r][i][j] = temp[mat_GF2_times_vec_GF2(NTL::inv(l[r-1][i]), (uint8_t)j)];
            }
        }
    }

    for (r = 0; r < 9; r++) {
        for (i = 0; i < 4; j++) {
            for (j = 0; j < 256; j++) {
                uint32_t a = mbl[r][i*4  ][j], 
                         b = mbl[r][i*4+1][j], 
                         c = mbl[r][i*4+2][j], 
                         d = mbl[r][i*4+3][j];

                mbl[r][i*4  ][j] = mat_GF2_times_vec_GF2(l[r][inv_shift_map[j*4  ]], (uint8_t)(a >> 24)) << 24 |
                                   mat_GF2_times_vec_GF2(l[r][inv_shift_map[j*4+1]], (uint8_t)(a >> 16)) << 16 |
                                   mat_GF2_times_vec_GF2(l[r][inv_shift_map[j*4+2]], (uint8_t)(a >>  8)) <<  8 |
                                   mat_GF2_times_vec_GF2(l[r][inv_shift_map[j*4+3]], (uint8_t)(a      ))       ;

                mbl[r][i*4+1][j] = mat_GF2_times_vec_GF2(l[r][inv_shift_map[j*4  ]], (uint8_t)(b >> 24)) << 24 |
                                   mat_GF2_times_vec_GF2(l[r][inv_shift_map[j*4+1]], (uint8_t)(b >> 16)) << 16 |
                                   mat_GF2_times_vec_GF2(l[r][inv_shift_map[j*4+2]], (uint8_t)(b >>  8)) <<  8 |
                                   mat_GF2_times_vec_GF2(l[r][inv_shift_map[j*4+3]], (uint8_t)(b      ))       ;

                mbl[r][i*4+2][j] = mat_GF2_times_vec_GF2(l[r][inv_shift_map[j*4  ]], (uint8_t)(c >> 24)) << 24 |
                                   mat_GF2_times_vec_GF2(l[r][inv_shift_map[j*4+1]], (uint8_t)(c >> 16)) << 16 |
                                   mat_GF2_times_vec_GF2(l[r][inv_shift_map[j*4+2]], (uint8_t)(c >>  8)) <<  8 |
                                   mat_GF2_times_vec_GF2(l[r][inv_shift_map[j*4+3]], (uint8_t)(c      ))       ;
                                   
                mbl[r][i*4+3][j] = mat_GF2_times_vec_GF2(l[r][inv_shift_map[j*4  ]], (uint8_t)(d >> 24)) << 24 |
                                   mat_GF2_times_vec_GF2(l[r][inv_shift_map[j*4+1]], (uint8_t)(d >> 16)) << 16 |
                                   mat_GF2_times_vec_GF2(l[r][inv_shift_map[j*4+2]], (uint8_t)(d >>  8)) <<  8 |
                                   mat_GF2_times_vec_GF2(l[r][inv_shift_map[j*4+3]], (uint8_t)(d      ))       ;
            }
        }
    }
}
