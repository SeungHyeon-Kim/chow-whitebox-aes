/*
    Implementation of Chow's Whitebox AES
        - Generate a encryption table of WBAES-128
*/

#include <iostream>
#include <fstream>
#include "wbaes_tables.h"

void WBAES_ENCRYPTION_TABLE::read(const char *file) {
    std::ifstream in( file, std::ios::in | std::ios::binary );
    
    if ( in.is_open() ) {
        in.read( reinterpret_cast<char*>(this->xor_tables), sizeof(this->xor_tables) );
        in.read( reinterpret_cast<char*>(this->mbl_tables), sizeof(this->mbl_tables) );
        in.read( reinterpret_cast<char*>(this->ty_boxes  ), sizeof(this->ty_boxes  ) );
        in.close();
    }
}

void WBAES_ENCRYPTION_TABLE::write(const char *file) {
    std::ofstream out( file, std::ios::out | std::ios::binary );

    if ( out.is_open() ) {
        out.write( reinterpret_cast<char*>(this->xor_tables), sizeof(this->xor_tables) );
        out.write( reinterpret_cast<char*>(this->mbl_tables), sizeof(this->mbl_tables) );
        out.write( reinterpret_cast<char*>(this->ty_boxes  ), sizeof(this->ty_boxes  ) );
        out.close();

        std::cout << "WBAES-128 Encryption table has been saved." << std::endl;
    }
}

/*
    Shift Maps
*/

void gen_xor_tables(uint8_t xor_tables[][AES_128_BLOCK / 4 * 24][16][16]) {
    int r, n, x, y;

    for ( r = 0; r < AES_128_ROUND - 1; r++ ) {
        for ( n = 0; n < AES_128_BLOCK / 4 * 24; n++ ) {
            for ( x = 0; x < 16; x++ ) {
                for ( y = 0; y < 16; y++ ) {
                    xor_tables[r][n][x][y] = x ^ y;
                }
            }
        }
    }
}

void gen_t_boxes(uint8_t t_boxes[][AES_128_BLOCK][256]) {
    int r, x;
}

