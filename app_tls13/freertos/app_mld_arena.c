/*
 * FOCAL hackathon - bump arena for mldsa-native's working buffers. See app_mld_arena.h.
 *
 * mldsa-native allocates a set of buffers per signing *attempt* while the
 * outer buffers (matrix, secret vectors) stay live, so the arena must give
 * memory back as soon as the most recent blocks are freed, not only when
 * everything is. Blocks are tracked on a small stack; freeing the top block
 * (or a block that becomes the top once later blocks are freed) lowers the
 * water mark. Out-of-order frees are tolerated: the block is marked and
 * reclaimed when it reaches the top.
 */
#include <string.h>

#include "app_mld_arena.h"

#define ARENA_ALIGN    64u
#define ARENA_MAX_LIVE 32

static uint8_t *s_base;
static size_t s_size, s_top, s_peak;
static struct
{
    size_t start;
    uint8_t freed;
} s_blk[ARENA_MAX_LIVE];
static int s_nblk;

void app_mld_arena_init(void *buf, size_t size)
{
    uintptr_t b = ((uintptr_t)buf + ARENA_ALIGN - 1u) & ~(uintptr_t)(ARENA_ALIGN - 1u);
    s_base      = (uint8_t *)b;
    s_size      = size - (size_t)(b - (uintptr_t)buf);
    s_top = s_peak = 0;
    s_nblk         = 0;
}

void app_mld_arena_reset(int zeroize)
{
    if (zeroize && s_base != NULL && s_peak != 0)
    {
        volatile uint8_t *p = s_base;
        for (size_t i = 0; i < s_peak; i++) p[i] = 0;
    }
    s_top  = 0;
    s_nblk = 0;
}

size_t app_mld_arena_peak(void)
{
    return s_peak;
}

size_t app_mld_arena_in_use(void)
{
    return s_top;
}

void *app_mld_aligned_alloc(size_t size)
{
    size = (size + ARENA_ALIGN - 1u) & ~(size_t)(ARENA_ALIGN - 1u);
    if (s_base == NULL || s_nblk >= ARENA_MAX_LIVE || s_top + size > s_size)
    {
        return NULL; /* mldsa-native reports MLD_ERR_OUT_OF_MEMORY */
    }
    void *p             = s_base + s_top;
    s_blk[s_nblk].start = s_top;
    s_blk[s_nblk].freed = 0;
    s_nblk++;
    s_top += size;
    if (s_top > s_peak) s_peak = s_top;
    return p;
}

void app_mld_aligned_free(void *p)
{
    if (p == NULL || s_base == NULL)
    {
        return;
    }
    const size_t off = (size_t)((uint8_t *)p - s_base);
    for (int i = s_nblk - 1; i >= 0; i--)
    {
        if (s_blk[i].start == off && !s_blk[i].freed)
        {
            s_blk[i].freed = 1;
            break;
        }
    }
    /* pop every freed block from the top: that is where the memory comes back */
    while (s_nblk > 0 && s_blk[s_nblk - 1].freed)
    {
        s_nblk--;
        s_top = s_blk[s_nblk].start;
    }
}
