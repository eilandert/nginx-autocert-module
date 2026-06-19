/*
 * Shared in-process slab arena for the challenge/alpn store unit tests.
 *
 * The store functions (ngx_autocert_challenge_*, ngx_autocert_alpn_*) operate
 * on an ngx_shm_zone_t whose shm.addr points at a real ngx_slab_pool_t. In the
 * server that arena is shared memory; here we back it with a plain malloc'd
 * buffer and run ngx_slab_init() over it exactly as ngx_init_zone_pool() does
 * (min_shift=3, addr/end set). Single-process, so the slab mutex is a no-op
 * fast path — ngx_shmtx_create with a NULL file gives the atomic spinlock.
 *
 * Globals the slab + crc32 code read (ngx_pagesize, ngx_pagesize_shift,
 * ngx_cacheline_size, the crc32 tables) are normally set by ngx_os_init(); we
 * set them directly so we need not pull the whole OS init in.
 */

#ifndef NGX_AUTOCERT_TEST_SLAB_H
#define NGX_AUTOCERT_TEST_SLAB_H

#include <ngx_config.h>
#include <ngx_core.h>

#include <unistd.h>      /* getpid / getpagesize */

/* A generous arena: the stores hold a handful of small nodes. */
#define NGX_AUTOCERT_TEST_ARENA  (2 * 1024 * 1024)

static u_char       *ngx_autocert_test_arena;
static ngx_shm_zone_t ngx_autocert_test_zone;

/*
 * Build a usable shm zone over a malloc'd arena. Returns the zone pointer the
 * store init/set/get/remove functions take. Must call ngx_autocert_test_globals
 * first. The zone's init callback (e.g. ngx_autocert_challenge_init_zone) is
 * invoked by the caller against the returned zone after the slab is live.
 */
static ngx_shm_zone_t *
ngx_autocert_test_zone_create(void)
{
    ngx_slab_pool_t  *sp;

    ngx_autocert_test_arena = malloc(NGX_AUTOCERT_TEST_ARENA);
    if (ngx_autocert_test_arena == NULL) {
        return NULL;
    }
    memset(ngx_autocert_test_arena, 0, NGX_AUTOCERT_TEST_ARENA);

    ngx_memzero(&ngx_autocert_test_zone, sizeof(ngx_shm_zone_t));
    ngx_autocert_test_zone.shm.addr = ngx_autocert_test_arena;
    ngx_autocert_test_zone.shm.size = NGX_AUTOCERT_TEST_ARENA;
    ngx_autocert_test_zone.shm.exists = 0;
    ngx_autocert_test_zone.shm.log = NULL;

    sp = (ngx_slab_pool_t *) ngx_autocert_test_arena;
    sp->end = ngx_autocert_test_arena + NGX_AUTOCERT_TEST_ARENA;
    sp->min_shift = 3;
    sp->addr = ngx_autocert_test_arena;

    if (ngx_shmtx_create(&sp->mutex, &sp->lock, NULL) != NGX_OK) {
        free(ngx_autocert_test_arena);
        ngx_autocert_test_arena = NULL;
        return NULL;
    }

    ngx_slab_init(sp);

    return &ngx_autocert_test_zone;
}

static void
ngx_autocert_test_zone_destroy(void)
{
    if (ngx_autocert_test_arena != NULL) {
        ngx_slab_pool_t  *sp = (ngx_slab_pool_t *) ngx_autocert_test_arena;
        ngx_shmtx_destroy(&sp->mutex);
        free(ngx_autocert_test_arena);
        ngx_autocert_test_arena = NULL;
    }
}

/*
 * Globals the slab + shmtx code reference that are normally provided by the
 * nginx process/posix init objects. We are single-process and never contend
 * the mutex, so trivial values suffice (ngx_ncpu==1 sends ngx_shmtx_lock down
 * its no-spin path immediately).
 */
ngx_pid_t  ngx_pid;
ngx_int_t  ngx_ncpu = 1;

void
ngx_debug_point(void)
{
    /* nginx aborts here under NGX_DEBUG; a unit run never hits it. */
}

/*
 * Minimal ngx_log / ngx_cycle so the store TUs link without the full nginx
 * core. ngx_crc32_table_init() and ngx_alloc() read ngx_cycle->log, so it must
 * be a valid (non-NULL) object, not the bare NULL pointer.
 */
static ngx_log_t     ngx_autocert_test_log;
static ngx_cycle_t   ngx_autocert_test_cycle;
volatile ngx_cycle_t *ngx_cycle = &ngx_autocert_test_cycle;

void
ngx_log_error_core(ngx_uint_t level, ngx_log_t *log, ngx_err_t err,
    const char *fmt, ...)
{
    (void) level; (void) log; (void) err; (void) fmt;
}

/*
 * Set up every global the slab + shmtx + crc32 paths read — normally done by
 * ngx_os_init() / the master process. Call once at the top of main(), BEFORE
 * creating the zone. In particular ngx_slab_sizes_init() must run after
 * ngx_pagesize is set: it derives ngx_slab_max_size / exact-size globals, and
 * without it ngx_slab_init() leaves them zero and every small allocation falls
 * through to the page allocator instead of the small/exact-slab paths the
 * server actually uses.
 */
static void
ngx_autocert_test_globals(void)
{
    ngx_autocert_test_cycle.log = &ngx_autocert_test_log;

    ngx_pid = getpid();           /* real pid so shmtx ownership is genuine */

    ngx_pagesize = (ngx_uint_t) getpagesize();
    for (ngx_pagesize_shift = 0;
         (1u << ngx_pagesize_shift) != ngx_pagesize;
         ngx_pagesize_shift++) { /* void */ }
    ngx_cacheline_size = 64;

    ngx_slab_sizes_init();
}


/* Deterministic xorshift PRNG (fixed seed => reproducible collision search). */
static uint32_t
ngx_autocert_test_xs32(uint32_t *st)
{
    uint32_t x = *st;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    *st = x;
    return x;
}

#define NGX_AUTOCERT_TEST_COLL_LEN  8

/*
 * Find two DISTINCT, equal-length byte strings (length NGX_AUTOCERT_TEST_COLL_
 * LEN) that collide under ngx_crc32_long, to exercise the stores' full-key
 * compare on a hash tie. We draw full-entropy bytes from one continuous
 * xorshift stream and record each in an open-addressing map keyed by crc32;
 * a slot whose stored hash matches the current one is a true 32-bit collision.
 * RANDOM bytes are essential: crc32 is linear, so structured/low-entropy
 * inputs (a counter over an alphabet) stay collision-free — only a
 * full-entropy stream collides by the birthday bound (~2^16 inputs).
 * Returns 1 and fills a/b on success, 0 if none in the (generous) budget.
 */
static int
ngx_autocert_test_crc32_collision(u_char *a, u_char *b)
{
    enum { BITS = 20, SLOTS = 1 << BITS, MASK = SLOTS - 1, N = 1 << 18,
           L = NGX_AUTOCERT_TEST_COLL_LEN };
    static uint32_t  key[SLOTS];          /* stored full hash, 0 == empty */
    static uint32_t  val[SLOTS];          /* index into seq[] */
    static u_char    seq[N][L];           /* the generated strings */
    uint32_t         st = 0x9e3779b9u;    /* fixed seed: reproducible */
    uint32_t         i, h, slot, j, k;

    memset(key, 0, sizeof(key));

    for (i = 0; i < N; i++) {
        for (k = 0; k < (uint32_t) L; k++) {
            seq[i][k] = (u_char) (ngx_autocert_test_xs32(&st) >> 24);
        }

        h = ngx_crc32_long(seq[i], L);
        if (h == 0) {
            continue;                     /* reserve 0 as the empty sentinel */
        }

        slot = h & MASK;
        for ( ;; ) {
            if (key[slot] == 0) {
                key[slot] = h;
                val[slot] = i;
                break;
            }
            if (key[slot] == h) {
                j = val[slot];            /* distinct preimage, same hash */
                if (memcmp(seq[j], seq[i], L) != 0) {
                    memcpy(a, seq[j], L);
                    memcpy(b, seq[i], L);
                    return 1;
                }
                break;
            }
            slot = (slot + 1) & MASK;
        }
    }
    return 0;
}

#endif /* NGX_AUTOCERT_TEST_SLAB_H */
