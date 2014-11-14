
#include "miner.h"
#include "logging.h"

void kryptohash_regenhash(struct work *work)
{
    unsigned char scratchpad[KPROOF_OF_WORK_SZ / 8];
#ifdef DATA_FLIP
    unsigned int data[KRATE / 8], datacopy[KRATE / 8]; // aligned for flip120

    memcpy(datacopy, work->data, KRATE / 8);
    flip120(data, datacopy);
    KSHAKE320((unsigned char*)&data, KRATE, scratchpad, KPROOF_OF_WORK_SZ / 8);
#else
    KSHAKE320(work->data, KRATE, scratchpad, KPROOF_OF_WORK_SZ / 8);
#endif
    KSHAKE320(scratchpad, KPROOF_OF_WORK_SZ, work->kryptohash, 40);
}

bool kryptohash_prepare_work(struct thr_info __maybe_unused *thr, struct work *work)
{
#ifdef DATA_FLIP
    unsigned int src[KRATE / 8], dst[KRATE / 8]; // aligned for flip120

    memcpy(src, work->data, KRATE / 8);
    flip120(dst, src);
    memcpy(work->blk.kryptohash_data, dst, sizeof(work->blk.kryptohash_data));
#else
    memcpy(work->blk.kryptohash_data, work->data, sizeof(work->blk.kryptohash_data));
#endif
    return true;
}
