#ifndef WBAES_H
#define WBAES_H

#include "wbaes_tables.h"

void shift_rows(uint8_t *in);
void ref_table(uint32_t uint32_tables[16][256], uint8_t xor_tables[96][16][16], uint8_t *in);
void wbaes_encrypt(WBAES_ENCRYPTION_TABLE &et, uint8_t *pt);

#endif /* WBAES_H */