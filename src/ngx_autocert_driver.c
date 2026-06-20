/*
 * ngx_autocert_driver — the ACME engine driver, run on worker 0.
 *
 * The ACME state machine (account bootstrap, order flow, renewal scheduler) is
 * process-agnostic: it only needs an nginx event loop, a cycle->log, and the
 * outbound TLS client. Rather than run it in a privileged master-spawned helper
 * (the old M4a model, which alone caused the cold-crash problem and was the
 * outlier vs angie's native acme and the official Rust nginx-acme — both drive
 * ACME from worker 0), it is armed from the http module's init_process, gated to
 * worker 0 (or single-process mode). The store dir and account.key are therefore
 * written by the worker user.
 *
 *   - ngx_autocert_driver_init_process() arms the one-shot kick timer (which
 *     builds the client + bootstraps the account, then arms the renewal
 *     scheduler). It runs inside the worker's normal event loop, so no signal
 *     setup, listening-socket close, or channel plumbing is needed — the worker
 *     already did all of that.
 *   - ngx_autocert_driver_exit_process() tears the engine state down on worker
 *     exit (frees the account, in-flight order, and outbound client).
 *
 * Engine TUs (account.c / order.c / acme.c / json.c / challenge.c / alpn.c) are
 * reused unchanged; only the driving process moved.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>

#include <sys/file.h>          /* flock(2) — interprocess singleton gate */

#include "ngx_autocert_driver.h"
#include "ngx_autocert_shared.h"
#include "ngx_autocert_acme.h"
#include "ngx_autocert_account.h"
#include "ngx_autocert_challenge.h"
#include "ngx_autocert_alpn.h"
#include "ngx_http_autocert_conf.h"    /* store-layout enum */
#include "ngx_autocert_order.h"
#include "ngx_http_autocert_crypto.h"


#define NGX_AUTOCERT_KICK         500     /* ms; defer first ACME fetch */
#define NGX_AUTOCERT_RELOCK       5000    /* ms; retry the singleton lock so the
                                           * surviving worker 0 takes over after a
                                           * reload/USR2 retires the prior holder */
#define NGX_AUTOCERT_KICK_RETRY   30000   /* ms; re-kick after a transient
                                           * bootstrap failure (client build /
                                           * OOM / register start) so the driver
                                           * doesn't sit idle until reload */
#define NGX_AUTOCERT_HTTP_TIMEOUT 30000   /* ms; per-request transport timeout */


static void ngx_autocert_kick_handler(ngx_event_t *ev);
static ngx_int_t ngx_autocert_driver_trylock(ngx_cycle_t *cycle);
static void ngx_autocert_relock_handler(ngx_event_t *ev);
static void ngx_autocert_account_done(ngx_autocert_account_t *acct,
    ngx_int_t rc);
static void ngx_autocert_start_order(ngx_cycle_t *cycle);
static void ngx_autocert_order_complete(ngx_autocert_order_t *order,
    ngx_int_t rc);


/*
 * The outbound ACME client, owned by the driver for its lifetime, built once
 * and reused for every request. The account bootstrap (M4d-2) runs once at
 * startup: directory -> newNonce -> newAccount.
 */
static ngx_autocert_acme_client_t  ngx_autocert_client;
static ngx_uint_t                   ngx_autocert_client_ready;
static ngx_autocert_account_t      *ngx_autocert_account;
static ngx_pool_t                  *ngx_autocert_account_pool;
static ngx_autocert_order_t        *ngx_autocert_order;
static ngx_pool_t                  *ngx_autocert_order_pool;
static ngx_uint_t                   ngx_autocert_test_seeded;
static ngx_uint_t                   ngx_autocert_test_alpn_seeded;
static ngx_event_t                  ngx_autocert_kick_timer;

/*
 * Interprocess singleton gate. The ACME engine must drive from EXACTLY ONE
 * process, but `ngx_worker == 0` alone only picks one worker PER GENERATION:
 * across a graceful reload or USR2 hot upgrade the retiring worker 0 and the
 * fresh worker 0 overlap, and both would otherwise arm the engine and race the
 * same account nonce / submit duplicate CA orders. An flock(LOCK_EX) on a lock
 * file in the store dir serializes them: only the lock holder arms the engine.
 * The kernel drops the lock when the holder exits (clean or crash), and the
 * loser retries on a slow timer so the survivor takes over with no gap.
 */
static ngx_fd_t                     ngx_autocert_lock_fd = -1;
static ngx_event_t                  ngx_autocert_relock_timer;



/*
 * One-shot startup kick: build the outbound client (TLS trust + resolver from
 * the HTTP config) on first fire, then GET the CA directory to prove the
 * transport end to end. Failures are logged, not fatal -- the driver keeps
 * running so the ACME flow (M4c+) can retry.
 */
static void
ngx_autocert_kick_handler(ngx_event_t *ev)
{
    ngx_cycle_t              *cycle = ev->data;
    ngx_pool_t               *pool;
    ngx_autocert_conf_t       acf;
    ngx_autocert_account_t   *acct;

    if (ngx_quit || ngx_terminate || ngx_exiting) {
        return;
    }

    if (ngx_autocert_get_conf(cycle, &acf) != NGX_OK || !acf.configured) {
        ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0,
                      "autocert: no http{} autocert config; driver idle");
        return;
    }

    ngx_log_debug3(NGX_LOG_DEBUG_CORE, cycle->log, 0,
                   "autocert: kick config ca \"%V\" names:%ui challenge:%ui",
                   &acf.ca, acf.names ? acf.names->nelts : 0,
                   (ngx_uint_t) acf.challenge);

    /* TEST-ONLY: seed the configured challenge into the shared store once, so
     * the :80 serve path can be exercised before the order flow exists. */
    if (!ngx_autocert_test_seeded
        && acf.challenge_zone != NULL && acf.test_token.len != 0)
    {
        ngx_autocert_test_seeded = 1;
        if (ngx_autocert_challenge_set(acf.challenge_zone, &acf.test_token,
                                       &acf.test_keyauth)
            == NGX_OK)
        {
            ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0,
                          "autocert: seeded test challenge token \"%V\"",
                          &acf.test_token);
        } else {
            ngx_log_error(NGX_LOG_ERR, cycle->log, 0,
                          "autocert: failed to seed test challenge token");
        }
    }

    /* TEST-ONLY (M10b): build the tls-alpn-01 challenge cert for the configured
     * domain once and seed it into the ALPN store, so the worker's ALPN serve
     * path can be exercised before the order wiring (M10c) exists. */
    if (!ngx_autocert_test_alpn_seeded
        && acf.alpn_zone != NULL && acf.test_alpn_domain.len != 0)
    {
        EVP_PKEY    *akey;
        X509        *acert;
        ngx_pool_t  *atmp;
        ngx_str_t    acert_pem, akey_pem;

        ngx_autocert_test_alpn_seeded = 1;

        atmp = ngx_create_pool(4096, cycle->log);
        akey = ngx_http_autocert_key_generate(acf.key_type);
        acert = NULL;

        if (atmp != NULL && akey != NULL) {
            acert = ngx_http_autocert_acme_tls_cert(akey,
                        &acf.test_alpn_domain, &acf.test_alpn_keyauth);
        }

        if (acert != NULL
            && ngx_http_autocert_cert_to_pem(atmp, acert, &acert_pem) == NGX_OK
            && ngx_http_autocert_key_to_pem(atmp, akey, &akey_pem) == NGX_OK
            && ngx_autocert_alpn_set(acf.alpn_zone, &acf.test_alpn_domain,
                                     &acert_pem, &akey_pem) == NGX_OK)
        {
            ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0,
                          "autocert: seeded test tls-alpn-01 cert for \"%V\"",
                          &acf.test_alpn_domain);
        } else {
            ngx_log_error(NGX_LOG_ERR, cycle->log, 0,
                          "autocert: failed to seed test tls-alpn-01 cert");
        }

        if (acert != NULL) {
            X509_free(acert);
        }
        if (akey != NULL) {
            ngx_http_autocert_key_free(akey);
        }
        if (atmp != NULL) {
            ngx_destroy_pool(atmp);
        }
    }

    if (!ngx_autocert_client_ready) {
        if (ngx_autocert_acme_client_create(&ngx_autocert_client, cycle,
                                            &acf.ca_certificate, acf.resolver,
                                            NGX_AUTOCERT_HTTP_TIMEOUT)
            != NGX_OK)
        {
            ngx_log_error(NGX_LOG_ERR, cycle->log, 0,
                          "autocert: failed to build ACME client");
            ngx_add_timer(ev, NGX_AUTOCERT_KICK_RETRY);   /* retry, don't idle */
            return;
        }
        ngx_autocert_client.resolver_timeout = acf.resolver_timeout * 1000;
        ngx_autocert_client_ready = 1;

        ngx_log_debug1(NGX_LOG_DEBUG_CORE, cycle->log, 0,
                       "autocert: ACME client ready, resolver timeout %M ms",
                       ngx_autocert_client.resolver_timeout);
    }

    /* Run the account bootstrap once. */
    if (ngx_autocert_account != NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_CORE, cycle->log, 0,
                       "autocert: account bootstrap already in progress/live");
        return;                         /* already registering / registered */
    }

    pool = ngx_create_pool(NGX_MIN_POOL_SIZE, cycle->log);
    if (pool == NULL) {
        ngx_add_timer(ev, NGX_AUTOCERT_KICK_RETRY);
        return;
    }

    ngx_autocert_account = ngx_pcalloc(pool,
                                       sizeof(ngx_autocert_account_t));
    if (ngx_autocert_account == NULL) {
        ngx_destroy_pool(pool);
        ngx_add_timer(ev, NGX_AUTOCERT_KICK_RETRY);
        return;
    }
    ngx_autocert_account_pool = pool;

    acct = ngx_autocert_account;
    acct->client = &ngx_autocert_client;
    acct->cycle = cycle;
    acct->log = cycle->log;
    acct->directory_url = acf.ca;
    acct->key_type = acf.key_type;
    acct->handler = ngx_autocert_account_done;
    acct->data = cycle;                 /* used to chain into the order flow */

    /* account key path = <autocert_path>/account.key */
    acct->key_path.len = acf.path.len + sizeof("/account.key") - 1;
    acct->key_path.data = ngx_pnalloc(pool, acct->key_path.len + 1);
    if (acct->key_path.data == NULL) {
        ngx_destroy_pool(pool);
        ngx_autocert_account = NULL;
        ngx_autocert_account_pool = NULL;
        ngx_add_timer(ev, NGX_AUTOCERT_KICK_RETRY);
        return;
    }
    {
        u_char *p = ngx_cpymem(acct->key_path.data, acf.path.data, acf.path.len);
        p = ngx_cpymem(p, "/account.key", sizeof("/account.key") - 1);
        *p = '\0';
    }

    ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0,
                  "autocert: registering ACME account via %V", &acf.ca);

    if (ngx_autocert_account_register(acct) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, cycle->log, 0,
                      "autocert: could not start ACME account registration");
        ngx_destroy_pool(pool);
        ngx_autocert_account = NULL;
        ngx_autocert_account_pool = NULL;
        ngx_add_timer(ev, NGX_AUTOCERT_KICK_RETRY);
    }
}


/*
 * Terminal callback of the account bootstrap. On failure the account is freed.
 * On success the account is kept ALIVE as the ACME session (it owns the kid,
 * key and current nonce that every later POST is signed with — M6a) and the
 * order flow is started for the first collected name. The CI asserts on the
 * success line emitted by the account module.
 */
static void
ngx_autocert_account_done(ngx_autocert_account_t *acct, ngx_int_t rc)
{
    ngx_cycle_t  *cycle = acct->data;

    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, acct->log, 0,
                      "autocert: ACME account registration failed");
        ngx_autocert_account_free(acct);            /* key + bootstrap pool */
        ngx_autocert_account = NULL;
        if (ngx_autocert_account_pool) {
            ngx_destroy_pool(ngx_autocert_account_pool);
            ngx_autocert_account_pool = NULL;
        }
        if (!ngx_quit && !ngx_terminate && !ngx_exiting
            && ngx_autocert_kick_timer.handler != NULL
            && !ngx_autocert_kick_timer.timer_set)
        {
            ngx_add_timer(&ngx_autocert_kick_timer, NGX_AUTOCERT_KICK_RETRY);
        }
        return;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_CORE, acct->log, 0,
                   "autocert: ACME account ready, kid \"%V\"", &acct->kid);

    /* Keep the account alive; chain into the order flow. */
    ngx_autocert_start_order(cycle);
}


/*
 * M8 renewal scheduler.
 *
 * Instead of ordering a single name once, the driver runs a periodic timer
 * (ngx_autocert_sched_timer). On each tick it walks the collected name set in
 * order; for each name it decides whether the stored certificate needs work
 * (no cert on disk yet, or inside its renew_before window) and, if so, launches
 * exactly one ACME order. Orders are serialised through the single global
 * ngx_autocert_order: the order's terminal callback (ngx_autocert_order_complete)
 * pumps the scan forward to the next due name. When the scan reaches the end
 * with no order in flight, the periodic timer is rearmed.
 *
 * Renewed certs land on disk via the M6b atomic store; the per-worker serve
 * path (M7) hot-reloads them on mtime change, so no config reload is needed.
 */

/* Periodic check interval, capped so we re-examine within a renew window. */
#define NGX_AUTOCERT_SCHED_INTERVAL  (12 * 60 * 60 * 1000)   /* 12h, ms ceiling */
/* Never sweep faster than this, even for a tiny renew_before (avoid busy-loop). */
#define NGX_AUTOCERT_SCHED_FLOOR     (60 * 1000)             /* 60s, ms */
/* First scan shortly after startup (account is registered by then). */
#define NGX_AUTOCERT_SCHED_INITIAL   (1000)                  /* 1s, ms */

/*
 * Per-name failure backoff: after a failed order for a name, hold off
 * retrying it for BASE << min(fails-1, MAXSHIFT) seconds, capped at CAP, so a
 * persistently failing name (bad DNS, ACME rate limit) doesn't get hammered
 * every sweep. A success clears it.
 */
#define NGX_AUTOCERT_BACKOFF_BASE    60          /* 60s first retry hold */
#define NGX_AUTOCERT_BACKOFF_MAXSHIFT 6          /* 60s..3840s growth */
#define NGX_AUTOCERT_BACKOFF_CAP     (60 * 60)   /* 1h ceiling, seconds */

typedef struct {
    time_t      next_eligible;   /* don't retry before this (0 = ready) */
    ngx_uint_t  fails;           /* consecutive failures */
} ngx_autocert_backoff_t;

static ngx_event_t              ngx_autocert_sched_timer;
static ngx_uint_t               ngx_autocert_sched_index;  /* next name to scan */
static ngx_uint_t               ngx_autocert_sched_cur;    /* name index in flight */
static ngx_autocert_backoff_t  *ngx_autocert_backoff;      /* per-name, [n] */
static ngx_uint_t               ngx_autocert_backoff_n;    /* array length */

static void ngx_autocert_sched_handler(ngx_event_t *ev);
static void ngx_autocert_sched_pump(ngx_cycle_t *cycle);
static ngx_int_t ngx_autocert_name_due(ngx_cycle_t *cycle,
    ngx_autocert_conf_t *acf, ngx_str_t *name);
static ngx_int_t ngx_autocert_start_order_for(ngx_cycle_t *cycle,
    ngx_autocert_conf_t *acf, ngx_str_t *name);
static void ngx_autocert_backoff_record(ngx_uint_t index, ngx_uint_t success);
static void ngx_autocert_backoff_hold(ngx_uint_t index, time_t when);


/*
 * Arm the renewal scheduler once the account is live. Called from
 * account_done; the first scan fires NGX_AUTOCERT_SCHED_INITIAL later so the
 * worker is fully settled.
 */
static void
ngx_autocert_start_order(ngx_cycle_t *cycle)
{
    if (ngx_autocert_sched_timer.handler != NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_CORE, cycle->log, 0,
                       "autocert: renewal scheduler already armed");
        return;                         /* already armed */
    }

    ngx_memzero(&ngx_autocert_sched_timer, sizeof(ngx_event_t));
    ngx_autocert_sched_timer.handler = ngx_autocert_sched_handler;
    ngx_autocert_sched_timer.data = cycle;
    ngx_autocert_sched_timer.log = cycle->log;
    /* Cancelable: the renewal interval is up to 12h, but a long pending timer
     * must NOT keep a gracefully-shutting-down worker alive (it would pin the
     * worker — and the singleton lock — open until the timer fires, so the next
     * generation's worker 0 can never take over). nginx skips cancelable timers
     * in ngx_event_no_timers_left(), so the worker exits promptly on reload. */
    ngx_autocert_sched_timer.cancelable = 1;

    ngx_add_timer(&ngx_autocert_sched_timer, NGX_AUTOCERT_SCHED_INITIAL);
    ngx_log_debug1(NGX_LOG_DEBUG_CORE, cycle->log, 0,
                   "autocert: renewal scheduler armed in %M ms",
                   (ngx_msec_t) NGX_AUTOCERT_SCHED_INITIAL);
}


/*
 * Timer tick: restart the scan from the first name and pump until either an
 * order is launched or the whole set is found up to date (which rearms us).
 */
static void
ngx_autocert_sched_handler(ngx_event_t *ev)
{
    ngx_cycle_t  *cycle = ev->data;

    if (ngx_autocert_order != NULL) {
        /* An order is still in flight from a previous tick; let its completion
         * drive the scan. Rearm so we don't lose the periodic beat. */
        ngx_log_debug0(NGX_LOG_DEBUG_CORE, cycle->log, 0,
                       "autocert: scheduler tick while order in flight");
        ngx_add_timer(&ngx_autocert_sched_timer, NGX_AUTOCERT_SCHED_INTERVAL);
        return;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, cycle->log, 0,
                   "autocert: scheduler sweep starting");
    ngx_autocert_sched_index = 0;
    ngx_autocert_sched_pump(cycle);
}


/*
 * Advance through the name set from ngx_autocert_sched_index, launching an
 * order for the first name that needs one. If none remain, rearm the periodic
 * timer for the next sweep.
 */
static void
ngx_autocert_sched_pump(ngx_cycle_t *cycle)
{
    ngx_autocert_conf_t   acf;
    ngx_str_t            *names, *name;

    ngx_memzero(&acf, sizeof(ngx_autocert_conf_t));

    if (ngx_autocert_order != NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_CORE, cycle->log, 0,
                       "autocert: scheduler pump paused, order in flight");
        return;                         /* one order at a time */
    }

    if (ngx_autocert_get_conf(cycle, &acf) != NGX_OK || !acf.configured) {
        goto rearm;
    }

    if (acf.names == NULL || acf.names->nelts == 0) {
        ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0,
                      "autocert: no server names collected; nothing to order");
        goto rearm;
    }
    if (acf.challenge_zone == NULL) {
        ngx_log_error(NGX_LOG_ERR, cycle->log, 0,
                      "autocert: no challenge zone; cannot run order");
        goto rearm;
    }

    names = acf.names->elts;

    /* Lazily size the per-name backoff array to the (stable, postconfig) name
     * set. Allocated from the cycle pool; if the count ever changes across a
     * reload spawns fresh workers, so a simple realloc-on-mismatch is
     * enough. */
    if (ngx_autocert_backoff == NULL
        || ngx_autocert_backoff_n != acf.names->nelts)
    {
        /* Guard the size multiply against wrap before allocating (nelts is
         * operator-controlled). A wrap would underallocate and later
         * backoff[i] would read/write out of bounds. */
        if (acf.names->nelts
            > NGX_MAX_SIZE_T_VALUE / sizeof(ngx_autocert_backoff_t))
        {
            ngx_log_error(NGX_LOG_ERR, cycle->log, 0,
                          "autocert: implausible server name count");
            ngx_autocert_backoff_n = 0;
            goto rearm;
        }

        ngx_autocert_backoff = ngx_pcalloc(cycle->pool,
            acf.names->nelts * sizeof(ngx_autocert_backoff_t));
        if (ngx_autocert_backoff == NULL) {
            ngx_autocert_backoff_n = 0;
            goto rearm;
        }
        ngx_autocert_backoff_n = acf.names->nelts;
    }

    while (ngx_autocert_sched_index < acf.names->nelts) {
        ngx_uint_t  i = ngx_autocert_sched_index++;

        name = &names[i];

        /* Honour the per-name failure backoff before any disk/clock check. */
        if (ngx_autocert_backoff[i].next_eligible > ngx_time()) {
            ngx_log_debug2(NGX_LOG_DEBUG_CORE, cycle->log, 0,
                           "autocert: name \"%V\" held by backoff until %T",
                           name, ngx_autocert_backoff[i].next_eligible);
            continue;
        }

        if (!ngx_autocert_name_due(cycle, &acf, name)) {
            ngx_log_debug1(NGX_LOG_DEBUG_CORE, cycle->log, 0,
                           "autocert: name \"%V\" not due", name);
            continue;
        }

        ngx_autocert_sched_cur = i;     /* record which name is in flight */

        if (ngx_autocert_start_order_for(cycle, &acf, name) == NGX_OK) {
            return;                     /* order_complete will pump again */
        }
        /* Launch failed (transient: pool/OOM) — treat as a failure for backoff
         * so we don't spin on it, then try the next name this sweep. */
        ngx_autocert_backoff_record(i, 0);
    }

rearm:

    /*
     * Sweep again no later than half the renew_before window, capped at the
     * 12h ceiling and floored so a tiny window can't busy-loop. A fixed 12h
     * would miss renew_before values shorter than 12h and let a cert expire
     * between sweeps.
     */
    {
        ngx_msec_t  interval = NGX_AUTOCERT_SCHED_INTERVAL;
        time_t      now = ngx_time();
        time_t      soonest = 0;
        ngx_uint_t  i;

        if (acf.configured && acf.renew_before > 0) {
            /* Compute in 64-bit: renew_before is time_t seconds; a large
             * operator value would overflow a 32-bit ngx_msec_t if narrowed
             * before the *1000, yielding a bogusly small (too-frequent)
             * interval. Clamp to the ceiling before narrowing. */
            uint64_t  half = (uint64_t) acf.renew_before * 1000 / 2;
            if (half < (uint64_t) interval) {
                interval = (ngx_msec_t) half;
            }
        }

        /* If any name is backing off, wake when its hold expires (so a 60s
         * backoff isn't stuck behind a 12h sweep). */
        for (i = 0; i < ngx_autocert_backoff_n; i++) {
            time_t  e = ngx_autocert_backoff[i].next_eligible;
            if (e > now && (soonest == 0 || e < soonest)) {
                soonest = e;
            }
        }
        if (soonest != 0) {
            ngx_msec_t  until = (ngx_msec_t) (soonest - now) * 1000;
            if (until < interval) {
                interval = until;
            }
        }

        if (interval < NGX_AUTOCERT_SCHED_FLOOR) {
            interval = NGX_AUTOCERT_SCHED_FLOOR;
        }
        ngx_add_timer(&ngx_autocert_sched_timer, interval);
    }
}


/*
 * Record the outcome of an order attempt for name `index` into its backoff
 * slot. Success clears the backoff; failure grows it exponentially
 * (BASE << min(fails-1, MAXSHIFT)), capped at CAP, so a persistently failing
 * name is retried with increasing delay instead of every sweep.
 */
static void
ngx_autocert_backoff_record(ngx_uint_t index, ngx_uint_t success)
{
    ngx_autocert_backoff_t  *b;
    ngx_uint_t               shift;
    time_t                   delay;

    if (ngx_autocert_backoff == NULL || index >= ngx_autocert_backoff_n) {
        return;
    }

    b = &ngx_autocert_backoff[index];

    if (success) {
        ngx_log_debug1(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0,
                       "autocert: clearing backoff for name index %ui", index);
        b->fails = 0;
        b->next_eligible = 0;
        return;
    }

    b->fails++;
    shift = b->fails - 1;
    if (shift > NGX_AUTOCERT_BACKOFF_MAXSHIFT) {
        shift = NGX_AUTOCERT_BACKOFF_MAXSHIFT;
    }

    delay = (time_t) NGX_AUTOCERT_BACKOFF_BASE << shift;
    if (delay > NGX_AUTOCERT_BACKOFF_CAP) {
        delay = NGX_AUTOCERT_BACKOFF_CAP;
    }

    b->next_eligible = ngx_time() + delay;
    ngx_log_debug3(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0,
                   "autocert: backoff for name index %ui fails:%ui until %T",
                   index, b->fails, b->next_eligible);
}


/*
 * Override a name's next-eligible time with a CA-supplied Retry-After deadline
 * (HTTP 429 rate limit). We push next_eligible no earlier than `when` — taking
 * the later of the exponential backoff already recorded and the CA's request —
 * so honouring the rate limit never shortens the hold. fails is left as the
 * failure path set it.
 */
static void
ngx_autocert_backoff_hold(ngx_uint_t index, time_t when)
{
    ngx_autocert_backoff_t  *b;

    if (ngx_autocert_backoff == NULL || index >= ngx_autocert_backoff_n) {
        return;
    }

    b = &ngx_autocert_backoff[index];
    if (when > b->next_eligible) {
        b->next_eligible = when;
        ngx_log_debug2(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0,
                       "autocert: Retry-After holds name index %ui until %T",
                       index, when);
    }
}


/*
 * Decide whether `name` needs an order now: true if no fullchain.pem is stored
 * yet, if it is unreadable/corrupt, or if it is inside the renew_before window
 * (now >= notAfter - renew_before).
 */
static ngx_int_t
ngx_autocert_name_due(ngx_cycle_t *cycle, ngx_autocert_conf_t *acf,
    ngx_str_t *name)
{
    u_char      path[NGX_MAX_PATH];
    u_char     *p;
    size_t      base;
    time_t      not_after, now;
    ngx_int_t   rc;
    ngx_uint_t  certbot;

    if (acf->path.len == 0) {
        ngx_log_debug1(NGX_LOG_DEBUG_CORE, cycle->log, 0,
                       "autocert: name \"%V\" due because store path is unset",
                       name);
        return 1;                       /* store path unset; let order log it */
    }

    /*
     * The name is used as a path segment under the store dir; reject anything
     * that could escape it (mirrors the M6b store writer's guard). An unsafe
     * name is a config error: skip it (logged), do NOT mark it due — an order
     * for it would only fail in the store step and loop every sweep.
     */
    if (name->len == 0 || name->data[0] == '.') {
        ngx_log_error(NGX_LOG_ERR, cycle->log, 0,
                      "autocert: refusing unsafe server name \"%V\"", name);
        return 0;
    }
    for (p = name->data; p < name->data + name->len; p++) {
        if (*p == '/' || *p == '\0') {
            ngx_log_error(NGX_LOG_ERR, cycle->log, 0,
                          "autocert: refusing unsafe server name \"%V\"", name);
            return 0;
        }
    }

    /*
     * fullchain path for the freshness check. Must match where the store
     * writer + serve path put it, per layout:
     *   secure:  <path>/<name>/fullchain.pem
     *   certbot: <path>/live/<name>/fullchain.pem
     * (a mismatch here would make a certbot-mode name look perpetually
     * un-issued and reissue every sweep.)
     */
    certbot = (acf->store == NGX_HTTP_AUTOCERT_STORE_CERTBOT);

    base = acf->path.len + (certbot ? sizeof("/live") - 1 : 0)
           + 1 + name->len + sizeof("/fullchain.pem");
    if (base > NGX_MAX_PATH) {
        ngx_log_error(NGX_LOG_ERR, cycle->log, 0,
                      "autocert: store path too long for \"%V\"", name);
        return 0;
    }

    p = ngx_cpymem(path, acf->path.data, acf->path.len);
    if (certbot) {
        p = ngx_cpymem(p, "/live", sizeof("/live") - 1);
    }
    *p++ = '/';
    p = ngx_cpymem(p, name->data, name->len);
    ngx_memcpy(p, "/fullchain.pem", sizeof("/fullchain.pem"));

    rc = ngx_http_autocert_cert_not_after((char *) path, &not_after);

    if (rc == NGX_DECLINED) {
        ngx_log_debug1(NGX_LOG_DEBUG_CORE, cycle->log, 0,
                       "autocert: name \"%V\" due because no cert is stored",
                       name);
        return 1;                       /* no cert yet -> issue */
    }
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_WARN, cycle->log, 0,
                      "autocert: cannot read notAfter of \"%s\"; reissuing",
                      path);
        return 1;                       /* corrupt/unreadable -> reissue */
    }

    now = ngx_time();
    if (now >= not_after - acf->renew_before) {
        ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0,
                      "autocert: \"%V\" within renew window (notAfter=%T)",
                      name, not_after);
        return 1;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_CORE, cycle->log, 0,
                   "autocert: cert for \"%V\" fresh until %T",
                   name, not_after);
    return 0;                           /* still fresh */
}


/*
 * Launch the M6a/M6b order flow for one name, reusing the live account as the
 * ACME session. Returns NGX_OK if the order started (ngx_autocert_order set);
 * NGX_ERROR otherwise (caller moves on to the next name).
 */
static ngx_int_t
ngx_autocert_start_order_for(ngx_cycle_t *cycle, ngx_autocert_conf_t *acf,
    ngx_str_t *name)
{
    ngx_pool_t            *pool;
    ngx_autocert_order_t  *order;

    if (ngx_autocert_order != NULL) {
        return NGX_ERROR;               /* already running */
    }

    pool = ngx_create_pool(NGX_MIN_POOL_SIZE, cycle->log);
    if (pool == NULL) {
        return NGX_ERROR;
    }

    order = ngx_pcalloc(pool, sizeof(ngx_autocert_order_t));
    if (order == NULL) {
        ngx_destroy_pool(pool);
        return NGX_ERROR;
    }

    /* The domain string aliases the HTTP main-conf pool, which outlives the
     * order; the order copies what it needs into its own pool internally. */
    order->account = ngx_autocert_account;
    order->log = cycle->log;
    order->directory_url = acf->ca;
    order->domain = *name;
    order->challenge_zone = acf->challenge_zone;
    order->challenge = acf->challenge;          /* M10c: http-01 / tls-alpn-01 */
    order->alpn_zone = acf->alpn_zone;          /* M10b store, used when alpn */
    order->key_type = acf->key_type;
    order->store = acf->store;
    order->store_path = acf->path;
    order->handler = ngx_autocert_order_complete;
    order->data = cycle;

    ngx_autocert_order = order;
    ngx_autocert_order_pool = pool;

    ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0,
                  "autocert: starting ACME order for \"%V\"", name);

    if (ngx_autocert_order_start(order) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, cycle->log, 0,
                      "autocert: could not start ACME order for \"%V\"", name);
        ngx_destroy_pool(pool);
        ngx_autocert_order = NULL;
        ngx_autocert_order_pool = NULL;
        return NGX_ERROR;
    }

    return NGX_OK;
}


/*
 * Terminal callback of the order flow. M6b runs the full issuance (finalize →
 * download → store), so NGX_OK here means the certificate is on disk. Whatever
 * the outcome, advance the renewal scan to the next due name (M8).
 */
static void
ngx_autocert_order_complete(ngx_autocert_order_t *order, ngx_int_t rc)
{
    ngx_cycle_t  *cycle = order->data;

    if (rc == NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, order->log, 0,
                      "autocert: certificate provisioned for \"%V\"",
                      &order->domain);
    } else {
        ngx_log_error(NGX_LOG_ERR, order->log, 0,
                      "autocert: ACME order failed for \"%V\"", &order->domain);
    }

    /* Record the outcome for the in-flight name's backoff: success clears it,
     * failure grows the per-name retry delay (don't hammer a failing name). */
    ngx_autocert_backoff_record(ngx_autocert_sched_cur, rc == NGX_OK);

    /* If the CA rate-limited us (429), honour its Retry-After: hold this name
     * at least until then, on top of the exponential backoff just recorded. */
    if (rc != NGX_OK && order->retry_after > 0) {
        ngx_autocert_backoff_hold(ngx_autocert_sched_cur, order->retry_after);
    }

    ngx_autocert_order_free(order);     /* drops token, frees order pool... */
    ngx_autocert_order = NULL;
    if (ngx_autocert_order_pool) {
        ngx_destroy_pool(ngx_autocert_order_pool);
        ngx_autocert_order_pool = NULL;
    }

    /* Continue the current sweep with the next name (or rearm if done). A
     * failed name is held off by its backoff slot; the next periodic tick
     * retries it once next_eligible passes. */
    ngx_autocert_sched_pump(cycle);
}



/*
 * Try to acquire the interprocess singleton lock: open (creating) the lock file
 * in the store dir and take a non-blocking exclusive flock. Returns NGX_OK if
 * this process now holds it, NGX_AGAIN if another process holds it (retry
 * later), NGX_ERROR on a hard failure (no config / can't build path / open
 * failed for a reason other than contention).
 *
 * The fd is kept open for the driver's lifetime (the lock lives as long as an
 * open fd holding it); exit_process / a crash closes it and the kernel releases.
 */
static ngx_int_t
ngx_autocert_driver_trylock(ngx_cycle_t *cycle)
{
    ngx_autocert_conf_t  acf;
    u_char               path[NGX_MAX_PATH];
    u_char              *p;

    if (ngx_autocert_lock_fd != -1) {
        return NGX_OK;                      /* already held */
    }

    if (ngx_autocert_get_conf(cycle, &acf) != NGX_OK || !acf.configured) {
        return NGX_ERROR;                   /* nothing configured; nothing to do */
    }

    if (acf.path.len + sizeof("/.driver.lock") > NGX_MAX_PATH) {
        ngx_log_error(NGX_LOG_ERR, cycle->log, 0,
                      "autocert: store path too long for lock file");
        return NGX_ERROR;
    }

    p = ngx_cpymem(path, acf.path.data, acf.path.len);
    p = ngx_cpymem(p, "/.driver.lock", sizeof("/.driver.lock") - 1);
    *p = '\0';

    ngx_autocert_lock_fd = open((char *) path, O_RDWR | O_CREAT | O_CLOEXEC,
                                0600);
    if (ngx_autocert_lock_fd == -1) {
        ngx_log_error(NGX_LOG_ERR, cycle->log, ngx_errno,
                      "autocert: open() lock file \"%s\" failed", path);
        return NGX_ERROR;
    }

    for ( ;; ) {
        if (flock(ngx_autocert_lock_fd, LOCK_EX | LOCK_NB) == 0) {
            break;
        }
        if (ngx_errno == NGX_EINTR) {
            continue;                       /* interrupted by a signal; retry */
        }
        if (ngx_errno == NGX_EAGAIN || ngx_errno == EWOULDBLOCK) {
            /* Another process (the prior generation's worker 0) holds it. */
            (void) close(ngx_autocert_lock_fd);
            ngx_autocert_lock_fd = -1;
            return NGX_AGAIN;
        }
        ngx_log_error(NGX_LOG_ERR, cycle->log, ngx_errno,
                      "autocert: flock() lock file \"%s\" failed", path);
        (void) close(ngx_autocert_lock_fd);
        ngx_autocert_lock_fd = -1;
        return NGX_ERROR;
    }

    return NGX_OK;                          /* we are now the sole driver */
}


/* Arm the kick timer (one-shot ACME bootstrap → renewal scheduler). */
static void
ngx_autocert_driver_arm(ngx_cycle_t *cycle)
{
    ngx_memzero(&ngx_autocert_kick_timer, sizeof(ngx_event_t));
    ngx_autocert_kick_timer.handler = ngx_autocert_kick_handler;
    ngx_autocert_kick_timer.data = cycle;
    ngx_autocert_kick_timer.log = cycle->log;
    ngx_autocert_kick_timer.cancelable = 1;     /* don't pin a shutting-down worker */
    ngx_add_timer(&ngx_autocert_kick_timer, NGX_AUTOCERT_KICK);

    ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0,
                  "autocert: ACME driver armed on worker 0, pid %P", ngx_pid);
}


/*
 * Relock retry. The previous holder (a retiring worker 0) has not released yet;
 * keep retrying on a slow timer so this survivor takes over the moment the lock
 * frees, with no driver gap.
 */
static void
ngx_autocert_relock_handler(ngx_event_t *ev)
{
    ngx_cycle_t  *cycle = ev->data;

    if (ngx_quit || ngx_terminate || ngx_exiting) {
        return;
    }

    switch (ngx_autocert_driver_trylock(cycle)) {

    case NGX_OK:
        ngx_autocert_driver_arm(cycle);
        return;                             /* acquired; stop retrying */

    case NGX_AGAIN:
        ngx_add_timer(&ngx_autocert_relock_timer, NGX_AUTOCERT_RELOCK);
        return;

    default:
        return;                             /* hard error; logged in trylock */
    }
}


/*
 * Worker-0 entry point. Called from the http module's init_process, already
 * gated to worker 0 (or single-process mode), inside the worker's running event
 * loop. Take the interprocess singleton lock; if held by a retiring prior-
 * generation worker, retry on a timer. Once held, arm the kick timer; everything
 * else (client build, account bootstrap, renewal scheduler) chains from there.
 * The worker already installed signal handlers, set up the event engine, and
 * kept its listening sockets (it serves the :80 / tls-alpn challenge), so no
 * helper-style process init is needed here.
 */
void
ngx_autocert_driver_init_process(ngx_cycle_t *cycle)
{
    switch (ngx_autocert_driver_trylock(cycle)) {

    case NGX_OK:
        ngx_autocert_driver_arm(cycle);
        break;

    case NGX_AGAIN:
        ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0,
                      "autocert: ACME driver lock held by prior generation; "
                      "worker 0 (pid %P) waiting to take over", ngx_pid);
        ngx_memzero(&ngx_autocert_relock_timer, sizeof(ngx_event_t));
        ngx_autocert_relock_timer.handler = ngx_autocert_relock_handler;
        ngx_autocert_relock_timer.data = cycle;
        ngx_autocert_relock_timer.log = cycle->log;
        ngx_autocert_relock_timer.cancelable = 1;   /* don't pin a shutting-down worker */
        ngx_add_timer(&ngx_autocert_relock_timer, NGX_AUTOCERT_RELOCK);
        break;

    default:
        break;                              /* not configured / error; idle */
    }
}


/*
 * Worker-0 teardown on exit_process. Best-effort: free the in-flight order, the
 * live account (account key + bootstrap pool), and the outbound client. The
 * kernel would reclaim everything on exit anyway, but freeing explicitly keeps
 * leak checkers (valgrind/asan CI) quiet and mirrors a clean worker shutdown.
 */
void
ngx_autocert_driver_exit_process(ngx_cycle_t *cycle)
{
    (void) cycle;

    if (ngx_autocert_kick_timer.timer_set) {
        ngx_del_timer(&ngx_autocert_kick_timer);
    }
    if (ngx_autocert_sched_timer.timer_set) {
        ngx_del_timer(&ngx_autocert_sched_timer);
    }
    if (ngx_autocert_relock_timer.timer_set) {
        ngx_del_timer(&ngx_autocert_relock_timer);
    }

    if (ngx_autocert_order != NULL) {
        ngx_autocert_order_free(ngx_autocert_order);
        ngx_autocert_order = NULL;
    }
    if (ngx_autocert_order_pool != NULL) {
        ngx_destroy_pool(ngx_autocert_order_pool);
        ngx_autocert_order_pool = NULL;
    }

    if (ngx_autocert_account != NULL) {
        ngx_autocert_account_free(ngx_autocert_account);
        ngx_autocert_account = NULL;
    }
    if (ngx_autocert_account_pool != NULL) {
        ngx_destroy_pool(ngx_autocert_account_pool);
        ngx_autocert_account_pool = NULL;
    }

    if (ngx_autocert_client_ready) {
        ngx_autocert_acme_client_destroy(&ngx_autocert_client);
        ngx_autocert_client_ready = 0;
    }

    /* Release the singleton lock (kernel drops it on close) so the next
     * generation's worker 0 can take over immediately. */
    if (ngx_autocert_lock_fd != -1) {
        (void) close(ngx_autocert_lock_fd);
        ngx_autocert_lock_fd = -1;
    }
}
