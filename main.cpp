/*
    Chow's Whitebox AES encryption test
        - encrypt data with WBAES and decrypt with AES
        - performance benchmark (speed, look-up counts)
*/

#include <iostream>
#include <iomanip>

#include "aes.h"
#include "wbaes.h"
#include "wbaes_tables.h"

void dump_hex(const uint8_t *in, const size_t size) {
    size_t i;

    for (i = 0; i < size; i++) {
        printf("%02x:", in[i]);

        if ( (i + 1) % 16 == 0 ) {
            printf("\n");
        }
    }
}

int main(void) {
    uint8_t aes_key[AES_128_KEY] = {0x00, };
    uint32_t aes_roundkey[11][4];
    WBAES_ENCRYPTION_TABLE *et = new WBAES_ENCRYPTION_TABLE();

    AES32_Enc_KeySchedule(aes_key, aes_roundkey);
    gen_encryption_table(*et, (uint8_t *)aes_roundkey);

    et->write("et.bin");

    dump_hex((uint8_t *)aes_roundkey , AES_128_ROUND_KEY);


    
    uint8_t pt1[16]{}, pt2[16]{}, ct[16]{};
    
    AES32_Encrypt(pt1, aes_roundkey, ct);
    wbaes_encrypt(*et, pt2);

    printf("AES32 OUTPUT: \n");
    dump_hex(ct , AES_128_BLOCK);
    printf("WBAES OUTPUT: \n");
    dump_hex(pt2, AES_128_BLOCK);

    return 0;
}
