#include <iostream>

#include "gf.h"


void gf_print(byte gf) {
    int coef;

    printf("%d = %02x = ", gf, gf);
    for (int i = 7; i >= 0; i--) {
        coef = (gf >> i) & 0x01;
        
        if (coef == 1) {
            std::cout << " + " << "x^" << i;
        }
    }

    std::cout << std::endl;
}

byte gf_add(byte gf1, byte gf2) {
    return gf1 ^ gf2;
}

byte gf_xtime(byte gf) {
    return ((gf >> 7) & 0x01 == 1) ? (gf << 1) ^ 0x1b : gf << 1;
}

byte gf_mul(byte f, byte g) {
    byte h = 0; 
    int coef;

    for (int i = 7; i >= 0; i--) {
        coef = (f >> i) & 0x01;     // a7, a6, a5, ... ,a0
        h = gf_xtime(h);
        
        if (coef == 1) {
            h = gf_add(h, g);
        }
    }

    return h;
}

byte gf_inv(byte f) {
    byte f_inv = 1, temp = f;

    for (int i = 0; i < 7; i++) {
        temp = gf_mul(temp, temp);
        f_inv = gf_mul(f_inv, temp);
    }

    return f_inv;
}

byte aes_affine(byte w) {
    byte A[8][8] = {  
        {1, 0, 0, 0, 1, 1, 1, 1},
        {1, 1, 0, 0, 0, 1, 1, 1},
        {1, 1, 1, 0, 0, 0, 1, 1},
        {1, 1, 1, 1, 0, 0, 0, 1},
        {1, 1, 1, 1, 1, 0, 0, 0},
        {0, 1, 1, 1, 1, 1, 0, 0},
        {0, 0, 1, 1, 1, 1, 1, 0},
        {0, 0, 0, 1, 1, 1, 1, 1}
    };
    byte b_vec[8] = { 1, 1, 0, 0, 0, 1, 1, 0 };
    byte w_vec[8], y_vec[8], y;

    for (int i = 0; i < 8; i++) {
        w_vec[i] = (w >> i) & 0x01;
    }

    for (int i = 0; i < 8; i++) {
        y_vec[i] = b_vec[i];
        for (int j = 0; j < 8; j++) {
            y_vec[i] ^= A[i][j] * w_vec[j];
        }
    }

    y = 0;
    byte temp_bit;
    for (int i = 0; i < 8; i++) {
        temp_bit = y_vec[i] << i;
        y ^= temp_bit;
    }
    return y;
}

void get_aes_Sbox(byte sbox[256]) {
    byte temp;

    sbox[0] = aes_affine(0);
    for (int i = 1; i < 256; i++) {
        temp = gf_inv(i);
        sbox[i] = aes_affine(temp);
    }
}

void get_aes_inv_Sbox(byte isbox[256]) {
    byte Sbox[256];
    get_aes_Sbox(Sbox);
    for (int i = 0; i < 256; i++) {
        isbox[Sbox[i]] = i;
    }
}
