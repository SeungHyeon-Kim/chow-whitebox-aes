#ifndef DEBUG_H
#define DEBUG_H

#include <iostream>
#include <cstdint>

typedef unsigned char byte;
typedef unsigned char   u8;
typedef unsigned int   u32;

#ifndef DEBUG_OUT
#define DEBUG_OUT 0
#endif


void dump_bytes(uint8_t src);
void dump_bytes(const uint8_t *src, const size_t len);

#endif /* DEBUG_H */