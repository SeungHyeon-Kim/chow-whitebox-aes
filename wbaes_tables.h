#ifndef WBAES_TABLES_H
#define WBAES_TABLES_H

#include <fstream>

#include "aes.h"
#include "debug.h"

/*
    Whitebox AES Tables
*/
struct WBAES_ENCRYPTION_TABLE {
    // uint8_t          i_tables[16][16][256]   ;
    // uint8_t      s_xor_tables[480][16][16]   ;
    uint8_t      r1_xor_tables[9][96][16][16];
    uint8_t      r2_xor_tables[9][96][16][16];
    // uint8_t      e_xor_tables[480][16][16]   ;
    uint8_t          last_box[16][256]   ;
    // uint8_t          last_box[16][16][256]   ;
    uint32_t       mbl_tables[9][16][256]    ;
    uint32_t         ty_boxes[9][16][256]    ;

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
     - External
*/
struct WBAES_EXT_ENCODING {
    uint8_t     ext_f[16][2][16];
    uint8_t inv_ext_f[16][2][16];

    uint8_t     ext_g[16][2][16];
    uint8_t inv_ext_g[16][2][16];
};

/*
    Non-linear Encoding
     - Internal
*/
struct WBAES_INT_ENCODING {
    /* IA, XOR-128 */
    // uint8_t           int_f[16][2][16];
    // uint8_t       inv_int_f[16][2][16];

    // uint8_t         int_xf[15][32][16];
    // uint8_t         int_yf[15][32][16];

    // uint8_t       int_outf[15][32][16];
    // uint8_t   inv_int_outf[15][32][16];

    /* Ty-Boxes, XOR-32 */
    uint8_t        int_s[9][16][8][16];
    uint8_t    inv_int_s[9][16][8][16];

    uint8_t       int_xs[9][12][8][16];
    uint8_t       int_ys[9][12][8][16];

    uint8_t     int_outs[9][12][8][16];
    uint8_t inv_int_outs[9][12][8][16];

    /* MBL-tables, XOR-32 */
    uint8_t        int_m[9][16][8][16];
    uint8_t    inv_int_m[9][16][8][16];

    uint8_t       int_xm[9][12][8][16];
    uint8_t       int_ym[9][12][8][16];

    uint8_t     int_outm[9][12][8][16];
    uint8_t inv_int_outm[9][12][8][16];

    /* IA, XOR-128 */
    // uint8_t           int_o[16][2][16];
    // uint8_t       inv_int_o[16][2][16];

    // uint8_t         int_xo[15][32][16];
    // uint8_t         int_yo[15][32][16];

    // uint8_t       int_outo[15][32][16];
    // uint8_t   inv_int_outo[15][32][16];
};

void encode_ext_x(uint8_t (*f)[2][16], uint8_t *x);
void decode_ext_x(uint8_t (*inv_f)[2][16], uint8_t *x);

void gen_encryption_table(WBAES_ENCRYPTION_TABLE &et, WBAES_EXT_ENCODING &ee, WBAES_INT_ENCODING &ie, uint32_t *roundkeys);

#endif /* WBAES_TABLES_H */