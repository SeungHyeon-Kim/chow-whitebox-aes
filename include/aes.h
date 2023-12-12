#ifndef AES_H
#define AES_H

#include "utils.h"


/*
    from (rijndael-alg-fst.h)
*/
#define GETU32(pt) (((u32)(pt)[0] << 24) ^ ((u32)(pt)[1] << 16) ^ ((u32)(pt)[2] <<  8) ^ ((u32)(pt)[3]))
#define PUTU32(ct, st) { (ct)[0] = (u8)((st) >> 24); (ct)[1] = (u8)((st) >> 16); (ct)[2] = (u8)((st) >>  8); (ct)[3] = (u8)(st); }

/*
    AES32 - Operations
*/
void aes32_round(u32 state[4], u32 rk[4]);
void aes32_inv_round(u32 state[4], u32 rk[4]);
void aes32_encrypt(byte pt[16], u32 rk[11][4], byte ct[16]);
void aes32_decrypt(byte ct[16], u32 rk[11][4], byte pt[16]);

/*
    AES32 - Key Schedule
*/
void aes32_enc_keyschedule(byte k[16], u32 rk[11][4]);
void aes32_dec_keyschedule(byte k[16], u32 rk[11][4]);

void aes8_keyschedule(byte k[16], byte rk[11][16]);

#endif /* AES_H */