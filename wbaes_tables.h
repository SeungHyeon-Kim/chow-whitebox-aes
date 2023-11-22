#ifndef WBAES_TABLES_H
#define WBAES_TABLES_H

#include "aes.h"
#include "debug.h"

/*
    Whitebox AES Tables
*/
struct WBAES_ENCRYPTION_TABLE {
    uint8_t  xor_tables[9][96][16][16];
    uint8_t    last_box[16][256]      ;
    uint32_t mbl_tables[9][16][256]   ;
    uint32_t   ty_boxes[9][16][256]   ;

    void read(const char* file);
    void write(const char* file);
};

void shift_rows(uint8_t *x);
void inv_shift_rows(uint8_t *x);
void add_rk(uint8_t *x, uint32_t *rk);

void gen_xor_tables(uint8_t (*xor_tables)[96][16][16]);
void gen_t_boxes(uint8_t (*t_boxes)[16][256], uint32_t *roundkeys);
void gen_tyi_tables(uint32_t (*tyi_tables)[256]);
void composite_t_tyi(uint8_t (*t_boxes)[16][256], uint32_t (*tyi_tables)[256], uint32_t (*ty_boxes)[16][256], uint8_t (*last_box)[256]);

void gen_encryption_table(WBAES_ENCRYPTION_TABLE &et, uint32_t *roundkeys);

#endif /* WBAES_TABLES_H */