#ifndef WBAES_TABLES_H
#define WBAES_TABLES_H

#include "aes.h"

struct WBAES_ENCRYPTION_TABLE {
    uint8_t  xor_tables[AES_128_ROUND - 1][96][16][16];
    uint32_t mbl_tables[AES_128_ROUND - 1][16][256]   ;
    uint32_t   ty_boxes[AES_128_ROUND    ][16][256]   ;

    void read(const char* file);
    void write(const char* file);
};



#endif /* WBAES_TABLES_H */