#ifndef GF2_MAT_H
#define GF2_MAT_H

#include "utils.h"


void gf_print(byte gf);

/*
  GF(2^8) Operations
*/
byte gf_add(byte gf1, byte gf2);
byte gf_xtime(byte gf);
byte gf_mul(byte f, byte g);
byte gf_inv(byte f);

/*
  AES Sbox
*/
byte aes_affine(byte w);
void get_aes_Sbox(byte sbox[256]);
void get_aes_inv_Sbox(byte isbox[256]);

#endif /* GF2_MAT_H */
