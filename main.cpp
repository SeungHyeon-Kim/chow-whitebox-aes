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

#define EPOCH       10000

/*
    Common Params
*/
uint8_t  pt1[16] = {0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a}, 
         pt2[16] = {0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a}, 
         ct[16] = {0x00, };
uint8_t  u8_aes_key[16] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
uint32_t u32_round_key[11][4], u32_inv_round_key[11][4];

long get_ms() {
    struct timespec t_val;
    clock_gettime(CLOCK_MONOTONIC, &t_val);
    return (t_val.tv_sec * 1000 + t_val.tv_nsec / 1000000);
}

void aes() {
    int i;
    double begin;

    puts("==================== AES-128 ====================");
    puts("[Ipnut]"); dump_bytes(pt1, 16); puts("");

    AES32_Encrypt(pt1, u32_round_key, ct);

    puts("[Output]"); dump_bytes(ct, 16); puts("");

    AES32_EqDecrypt(ct, u32_inv_round_key, pt1);

    puts("[Decrypted]"); dump_bytes(pt1, 16);
    puts("=================================================");

    begin = get_ms();
    for (i = 0; i < EPOCH; i++) {
        AES32_Encrypt(pt1, u32_round_key, ct);
    }
    printf("elapsed : (1 avg) %.4fms\n", (get_ms() - begin) / EPOCH);
}

void wbaes() {
    int i;
    double begin;

    WBAES_ENCRYPTION_TABLE *et = new WBAES_ENCRYPTION_TABLE();
    WBAES_EXT_ENCODING     *ee = new WBAES_EXT_ENCODING();
    WBAES_INT_ENCODING     *ie = new WBAES_INT_ENCODING();

    gen_encryption_table(*et, *ee, *ie, (uint32_t *)u32_round_key);
    // et->write("et.bin");

    puts("===================== WBAES =====================");
    puts("[Ipnut]"); dump_bytes(pt2, 16); puts("");

    encode_ext_x(ee->ext_f, pt2);

    puts("[ExtA(Ipnut)]"); dump_bytes(pt2, 16); puts("");

    wbaes_encrypt(*et, pt2);

    puts("[Output]"); dump_bytes(pt2, 16); puts("");

    encode_ext_x(ee->ext_g, pt2);

    puts("[ExtB(Output)]"); dump_bytes(pt2, 16); puts("");

    AES32_EqDecrypt(pt2, u32_inv_round_key, ct);

    puts("[Decrypted]"); dump_bytes(ct, 16);
    puts("=================================================");

    begin = get_ms();
    for (i = 0; i < EPOCH; i++) {
        wbaes_encrypt(*et, pt2);
    }
    printf("elapsed : (1 avg) %.4fms\n", (get_ms() - begin) / EPOCH);

    delete et;
    delete ee;
    delete ie;
}

int main(int argc, char *argv[]) {
    AES32_Enc_KeySchedule(u8_aes_key, u32_round_key);
    AES32_Dec_KeySchedule(u8_aes_key, u32_inv_round_key);

    if (argc > 3) {
        printf("retry ./main or ./main aes or ./main wbaes");
        return -1;
    }

    if (argc == 2) {
        if (std::strcmp(argv[1], "aes") == 0) {
        aes();
        }
        else if (std::strcmp(argv[1], "wbaes") == 0) {
            wbaes();
        }
        else {
            printf("retry ./main or ./main aes or ./main wbaes");
            return -1;
        }
    }
    else {
        aes();
        wbaes();
    }

    return 0;
}
