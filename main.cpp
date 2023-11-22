/*
    Chow's Whitebox AES encryption test
        - encrypt data with WBAES and decrypt with AES
        - performance benchmark (speed, look-up counts)
*/

#include <iostream>

#include "aes.h"
#include "wbaes.h"
#include "wbaes_tables.h"
#include "debug.h"

int main(void) {
    uint8_t   u8_aes_key[16] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
    uint32_t  u32_round_key[11][4];
    
    WBAES_ENCRYPTION_TABLE *et = new WBAES_ENCRYPTION_TABLE();

    AES32_Enc_KeySchedule(u8_aes_key, u32_round_key);
    gen_encryption_table(*et, (uint32_t *)u32_round_key);

    et->write("et.bin");
    
    uint8_t pt1[16] = {0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a}, 
            pt2[16]{}, ct[16]{};
    memcpy(pt2, pt1, 16);
    
    AES32_Encrypt(pt1, u32_round_key, ct);
    wbaes_encrypt(*et, pt2);

    printf("AES32 OUTPUT: \n");
    dump_bytes(ct , 16);
    
    printf("WBAES OUTPUT: \n");
    dump_bytes(pt2, 16);

    delete et;
    return 0;
}
