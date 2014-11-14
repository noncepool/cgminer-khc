#ifndef KRYPTOHASH_H
#define KRYPTOHASH_H

#include "sha3/sha3.h"

#define KSHAKE320_L             (320)  // Length in bits
#define KRATE                   (960)  // Keccak rate in bits
#define KPROOF_OF_WORK_SZ (546*KRATE)  // KryptoHash Proof of Work Size in bits

struct uint320
{
    unsigned char v[40];
};
typedef struct uint320 uint320;


#endif