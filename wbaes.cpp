/*
    Implementation of Chow's Whitebox AES
        - Encrypt on the whiteboxing algorithm
*/
#include "wbaes.h"

extern uint8_t     shift_map[16];


/*
    A Tutorial on Whitebox AES
            J.A. Muir
     
     - 3.6 pseudo algo.
        state = plaintext
        for r = 1 ... 9
            ShiftRows(state)
            TBoxesTyiTables(state)  ----- ty_boxes   & xor_tables
            XORTables(state)        ----- mbl_tables & xor_tables
        ShiftRows(state)
        TBoxes(state, 10)           ----- last_box
        chipertext = state
*/

static void shift_rows(uint8_t *x) {
    int i;
    uint8_t temp[16];

    memcpy(temp, x, 16);

    for (i = 0; i < 16; i++) {
        x[i] = temp[shift_map[i]];
    }
}

// static void ia(const uint8_t (*tables)[256], const uint8_t (*i_xor_tables)[16][16], const uint8_t (*ext)[2][16], uint8_t *in) {
//     int i, j;
//     uint8_t temp[16][16];

//     for (i = 0; i < 16; i++) {
//         temp[i][i] = in[i];
//         for (j = 0; j < 16; j++) {
//             if (i != j) {
//                 temp[i][j] = tables[i][ext[i][1][0] << 4 | ext[i][0][0]];
//             }
//             else {
//                 temp[i][j] = tables[i][temp[i][j]];
//             }
//         }
//     }

//     for (i = 0; i < 8; i++) {
//         for (j = 0; j < 16; j++) {
//             temp[i][j] = (
//                 i_xor_tables[(i<<5)+(j<<1)  ][(temp[(i<<1)][j] >> 4) & 0xf][(temp[(i<<1)+1][j] >> 4) & 0xf] << 4 | 
//                 i_xor_tables[(i<<5)+(j<<1)+1][(temp[(i<<1)][j])      & 0xf][(temp[(i<<1)+1][j])      & 0xf]      
//             );
//         }
//     }

//     for (i = 8; i < 12; i++) {
//         for (j = 0; j < 16; j++) {
//             temp[i][j] = (
//                 i_xor_tables[(i<<5)+(j<<1)  ][(temp[(i-8)*2][j] >> 4) & 0xf][(temp[((i-8)*2)+1][j] >> 4) & 0xf] << 4 |
//                 i_xor_tables[(i<<5)+(j<<1)+1][(temp[(i-8)*2][j])      & 0xf][(temp[((i-8)*2)+1][j])      & 0xf]      
//             );
//         }
//     }

//     for (j = 0; j < 16; j++) {
//         temp[12][j] = (
//             i_xor_tables[384+(j<<1)  ][(temp[8][j] >> 4) & 0xf][(temp[9][j] >> 4) & 0xf] << 4 |
//             i_xor_tables[384+(j<<1)+1][(temp[8][j])      & 0xf][(temp[9][j])      & 0xf]      
//         );
//         temp[13][j] = (
//             i_xor_tables[416+(j<<1)  ][(temp[10][j] >> 4) & 0xf][(temp[11][j] >> 4) & 0xf] << 4 |
//             i_xor_tables[416+(j<<1)+1][(temp[10][j])      & 0xf][(temp[11][j])      & 0xf]      
//         );
//         in[j] = (
//             i_xor_tables[448+(j<<1)  ][(temp[12][j] >> 4) & 0xf][(temp[13][j] >> 4) & 0xf] << 4 |
//             i_xor_tables[448+(j<<1)+1][(temp[12][j])      & 0xf][(temp[13][j])      & 0xf]      
//         );
//     }
// }

static void ref_table(const uint32_t (*tables)[256], const uint8_t (*xor_tables)[16][16], uint8_t *in) {
    int i;
    uint32_t a, b, c, d;

    for (i = 0; i < 4; i++) {
        a = tables[i*4  ][in[i*4  ]];
        b = tables[i*4+1][in[i*4+1]];
        c = tables[i*4+2][in[i*4+2]];
        d = tables[i*4+3][in[i*4+3]];

        in[i*4  ] = (
            (xor_tables[64+(i*8)  ][xor_tables[i*16  ][(a >> 28) & 0xf][(b >> 28) & 0xf]][xor_tables[i*16+8][(c >> 28) & 0xf][(d >> 28) & 0xf]]) << 4 |
            (xor_tables[64+(i*8)+1][xor_tables[i*16+1][(a >> 24) & 0xf][(b >> 24) & 0xf]][xor_tables[i*16+9][(c >> 24) & 0xf][(d >> 24) & 0xf]])
        );
        in[i*4+1] = (
            (xor_tables[64+(i*8)+2][xor_tables[i*16+2][(a >> 20) & 0xf][(b >> 20) & 0xf]][xor_tables[i*16+10][(c >> 20) & 0xf][(d >> 20) & 0xf]]) << 4 |
            (xor_tables[64+(i*8)+3][xor_tables[i*16+3][(a >> 16) & 0xf][(b >> 16) & 0xf]][xor_tables[i*16+11][(c >> 16) & 0xf][(d >> 16) & 0xf]])
        );
        in[i*4+2] = (
            (xor_tables[64+(i*8)+4][xor_tables[i*16+4][(a >> 12) & 0xf][(b >> 12) & 0xf]][xor_tables[i*16+12][(c >> 12) & 0xf][(d >> 12) & 0xf]]) << 4 |
            (xor_tables[64+(i*8)+5][xor_tables[i*16+5][(a >>  8) & 0xf][(b >>  8) & 0xf]][xor_tables[i*16+13][(c >>  8) & 0xf][(d >>  8) & 0xf]])
        );
        in[i*4+3] = (
            (xor_tables[64+(i*8)+6][xor_tables[i*16+6][(a >>  4) & 0xf][(b >>  4) & 0xf]][xor_tables[i*16+14][(c >>  4) & 0xf][(d >>  4) & 0xf]]) << 4 |
            (xor_tables[64+(i*8)+7][xor_tables[i*16+7][(a      ) & 0xf][(b      ) & 0xf]][xor_tables[i*16+15][(c      ) & 0xf][(d      ) & 0xf]])
        );
    }
}

void wbaes_encrypt(const WBAES_ENCRYPTION_TABLE &et, uint8_t *pt) {
    int r;

    // ia(et.i_tables, et.s_xor_tables, ee.ext_f, pt);
    #if DEBUG_OUT
    puts("Round ----------------------------------------");
    #endif

    for (r = 0; r < 9; r++) {
        shift_rows(pt);
        ref_table(et.ty_boxes[r]  , et.r1_xor_tables[r], pt);
        ref_table(et.mbl_tables[r], et.r2_xor_tables[r], pt);

        #if DEBUG_OUT
        printf("[%02d] ", r); dump_bytes(pt, 16);
        #endif
    }
    shift_rows(pt);

    // ia(et.last_box, et.e_xor_tables, ee.ext_g, pt);

    pt[0 ] = et.last_box[0 ][pt[0 ]];
    pt[1 ] = et.last_box[1 ][pt[1 ]];
    pt[2 ] = et.last_box[2 ][pt[2 ]];
    pt[3 ] = et.last_box[3 ][pt[3 ]];
    pt[4 ] = et.last_box[4 ][pt[4 ]];
    pt[5 ] = et.last_box[5 ][pt[5 ]];
    pt[6 ] = et.last_box[6 ][pt[6 ]];
    pt[7 ] = et.last_box[7 ][pt[7 ]];
    pt[8 ] = et.last_box[8 ][pt[8 ]];
    pt[9 ] = et.last_box[9 ][pt[9 ]];
    pt[10] = et.last_box[10][pt[10]];
    pt[11] = et.last_box[11][pt[11]];
    pt[12] = et.last_box[12][pt[12]];
    pt[13] = et.last_box[13][pt[13]];
    pt[14] = et.last_box[14][pt[14]];
    pt[15] = et.last_box[15][pt[15]];

    #if DEBUG_OUT
    printf("[10] "); dump_bytes(pt, 16);
    puts("----------------------------------------------");
    #endif
}
