#ifndef WBAES_TABLES_H
#define WBAES_TABLES_H

#include <fstream>

#include "aes.h"
#include "debug.h"

/*
    Whitebox AES Tables
*/
struct WBAES_ENCRYPTION_TABLE {
    uint8_t          i_tables[16][256]      ;
    uint8_t      s_xor_tables[480][16][16]  ;
    uint8_t      r_xor_tables[9][96][16][16];
    uint8_t      e_xor_tables[480][16][16]  ;
    uint8_t          last_box[16][256]      ;
    uint32_t       mbl_tables[9][16][256]   ;
    uint32_t         ty_boxes[9][16][256]   ;

    explicit WBAES_ENCRYPTION_TABLE() {};

    inline void read(const char* file) {
        std::ifstream in(file, std::ios::in | std::ios::binary);
    
        if ( in.is_open() ) {
            in.read((char *)this, sizeof(*this));
            in.close();
        }
    }
    inline void write(const char* file) const {
        std::ofstream out(file, std::ios::out | std::ios::binary);

        if ( out.is_open() ) {
            out.write((char *)this, sizeof(*this));
            out.close();
        }
    }
};

/*
    Non-linear Encoding
     - External & Internal
*/
struct WBAES_NONLINEAR_ENCODING {
    /* External */
    uint8_t     ext_f[16][2][16];
    uint8_t inv_ext_f[16][2][16];

    /* Internal (IA, XOR-128) */
    uint8_t           int_f[16][2][16];
    uint8_t       inv_int_f[16][2][16];

    uint8_t         int_xf[15][32][16];
    uint8_t         int_yf[15][32][16];

    uint8_t       int_outf[15][32][16];
    uint8_t   inv_int_outf[15][32][16];

    /* Internal - (Ty-Boxes, XOR-32) */
    uint8_t        int_s[9][16][8][16];
    uint8_t    inv_int_s[9][16][8][16];

    uint8_t       int_xs[9][12][8][16];
    uint8_t       int_ys[9][12][8][16];

    uint8_t     int_outs[9][12][8][16];
    uint8_t inv_int_outs[9][12][8][16];

    // /* Internal - III */
    // uint8_t     int_h[9][16][8][16];
    // uint8_t inv_int_h[9][16][8][16];

    // /* Internal - IV */
    // uint8_t     int_k[9][96][8][16];
    // uint8_t inv_int_k[9][96][8][16];

    // /* Internal - V */
    // uint8_t     int_l[16][4][8][16];
    // uint8_t inv_int_l[16][4][8][16];
};

void encode_ext_x(uint8_t (*f)[2][16], uint8_t *x);
void decode_ext_x(uint8_t (*inv_f)[2][16], uint8_t *x);

void gen_encryption_table(WBAES_ENCRYPTION_TABLE &et, WBAES_NONLINEAR_ENCODING &en, uint32_t *roundkeys);

#endif /* WBAES_TABLES_H */