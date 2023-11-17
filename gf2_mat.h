#ifndef GF2_MAT_H
#define GF2_MAT_H

#include <iostream>
#include <NTL/mat_GF2.h>

typedef unsigned char byte;

byte GF_add(byte gf1, byte gf2);
byte GF_xtime(byte gf);
byte GF_mul(byte f, byte g);
byte GF_inv(byte f);
void GF_print(byte gf);

byte AES_Affine(byte w);

void Get_AES_Sbox(byte sbox[256]);
void Get_AES_Inv_Sbox(byte isbox[256]);

NTL::mat_GF2 gen_gf2_rand_matrix(int dimension);
NTL::mat_GF2 gen_gf2_rand_invertible_matrix(int dimension);
NTL::vec_GF2 scalar_to_vec_GF2(const uint8_t src);
NTL::vec_GF2 scalar_to_vec_GF2(const uint32_t src);
template <typename T>
T vec_GF2_to_scalar(const NTL::vec_GF2 &src);
uint8_t mat_GF2_times_vec_GF2(const NTL::mat_GF2 &x, const uint8_t y);
uint32_t mat_GF2_times_vec_GF2(const NTL::mat_GF2 &x, const uint32_t y);


#endif /* GF2_MAT_H */