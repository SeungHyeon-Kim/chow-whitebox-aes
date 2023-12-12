#ifndef WBAES_H
#define WBAES_H

#include "wbaes_tables.h"

/**
 * @brief
 *  AES-128 encryption using a whitebox encryption table
 * @param et    Whitebox Encryption Table
 * @param pt    Plaintext
*/
void wbaes_encrypt(const WBAES_ENCRYPTION_TABLE &et, uint8_t *pt);

#endif /* WBAES_H */
