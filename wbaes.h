#ifndef WBAES_H
#define WBAES_H

#include "wbaes_tables.h"

void wbaes_encrypt(const WBAES_ENCRYPTION_TABLE &et, uint8_t *pt);

#endif /* WBAES_H */