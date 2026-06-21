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
#include <sys/stat.h>          /* mkdir(2) — M3 per-CA account dirs */
#include <fcntl.h>             /* AT_FDCWD — M3 atomic key migration */

/*
 * M3: migrate the legacy account key with RENAME_NOREPLACE so it can never
 * clobber a key that appeared at the destination after our absence check
 * (renameat2 is Linux 3.15+; called via syscall() to avoid a glibc wrapper
 * dependency, with a plain rename() fallback on ENOSYS/EINVAL — mirrors the
 * RENAME_EXCHANGE use in ngx_autocert_order.c).
 */
#if defined(__linux__)
#include <sys/syscall.h>
#ifndef RENAME_NOREPLACE
#define RENAME_NOREPLACE (1 << 0)
#endif
#endif

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


/*
 * M5 per-name failure backoff slot. Defined up here (was below the scheduler
 * section) because each CA's state now carries its own per-name backoff array.
 */
typedef struct {
    time_t      next_eligible;   /* don't retry before this (0 = ready) */
    ngx_uint_t  fails;           /* consecutive failures */
} ngx_autocert_backoff_t;


/*
 * M5 multi-engine driver: one ACME engine per distinct CA the instance issues
 * against (ngx_autocert_conf.ca_list, an ngx_autocert_ca_entry_t array grouped
 * by effective CA at postconfig). Each CA gets its own outbound client, its own
 * registered account (with that CA's directory URL + EAB), and its own per-name
 * backoff array. A SINGLE order is in flight across all CAs at any time
 * (ngx_autocert_order below) and the renewal scheduler walks CAs × names with a
 * (ca, name) cursor, so the ACME flows never overlap. Account bootstrap is
 * SEQUENTIAL: CA[i]'s registration terminal starts CA[i+1]'s; when the last
 * account is live (or skipped) the scheduler is armed.
 */
typedef struct {
    ngx_autocert_ca_entry_t     *entry;        /* &ca_list[i]: ca_conf,names,hash,key */
    ngx_autocert_acme_client_t   client;       /* per-CA outbound client */
    ngx_uint_t                   client_ready;
    ngx_autocert_account_t      *account;      /* per-CA registered account */
    ngx_pool_t                  *account_pool;
    ngx_uint_t                   account_live;  /* registration succeeded */
    ngx_autocert_backoff_t      *backoff;      /* per-name, [entry->names->nelts] */
    ngx_uint_t                   backoff_n;
} ngx_autocert_ca_state_t;


static void ngx_autocert_kick_handler(ngx_event_t *ev);
static ngx_int_t ngx_autocert_driver_trylock(ngx_cycle_t *cycle);
static void ngx_autocert_relock_handler(ngx_event_t *ev);
static void ngx_autocert_account_done(ngx_autocert_account_t *acct,
    ngx_int_t rc);
static void ngx_autocert_bootstrap_ca(ngx_cycle_t *cycle, ngx_uint_t ca_idx);
static void ngx_autocert_start_order(ngx_cycle_t *cycle);
static void ngx_autocert_order_complete(ngx_autocert_order_t *order,
    ngx_int_t rc);


/*
 * The per-CA engines (clients + accounts + backoff), allocated once from the
 * cycle pool at the first kick, one entry per ca_list CA. NULL until the kick
 * builds them.
 */
static ngx_autocert_ca_state_t     *ngx_autocert_ca_states;
static ngx_uint_t                   ngx_autocert_ca_states_n;
static ngx_cycle_t                 *ngx_autocert_cycle;     /* for account_done */

/*
 * A single ACME order is in flight at a time across every CA — serialised by
 * the scheduler's (ca, name) cursor. The order carries its CA's account +
 * directory URL, so one global order slot suffices.
 */
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
 * M3: rename old->new without ever replacing an existing new (RENAME_NOREPLACE).
 * Returns NGX_OK on success; NGX_ERROR otherwise with ngx_errno set (EEXIST when
 * new already exists). Falls back to plain rename() only where renameat2 is
 * unavailable (old kernel) — the caller's prior ENOENT check bounds that race.
 */
static ngx_int_t
ngx_autocert_rename_noreplace(u_char *oldp, u_char *newp)
{
#if defined(__linux__) && defined(SYS_renameat2)
    if (syscall(SYS_renameat2, AT_FDCWD, (const char *) oldp,
                AT_FDCWD, (const char *) newp, RENAME_NOREPLACE) == 0)
    {
        return NGX_OK;
    }
    if (ngx_errno != NGX_ENOSYS && ngx_errno != EINVAL) {
        return NGX_ERROR;       /* real error (incl. EEXIST) — caller inspects */
    }
    /* fall through: kernel/fs without renameat2 */
#endif
    if (rename((char *) oldp, (char *) newp) == 0) {
        return NGX_OK;
    }
    return NGX_ERROR;
}


/*
 * M3: mkdir a 0700 dir, tolerating an existing real directory (EEXIST) but
 * rejecting a planted symlink/non-dir. Mirrors the store writer's guard.
 */
static ngx_int_t
ngx_autocert_mkdir_secure(ngx_cycle_t *cycle, u_char *dir)
{
    struct stat  st;

    if (mkdir((char *) dir, 0700) == -1) {
        if (ngx_errno != NGX_EEXIST) {
            ngx_log_error(NGX_LOG_ERR, cycle->log, ngx_errno,
                          "autocert: mkdir(\"%s\") failed", dir);
            return NGX_ERROR;
        }
        if (lstat((char *) dir, &st) == -1 || !S_ISDIR(st.st_mode)) {
            ngx_log_error(NGX_LOG_ERR, cycle->log, ngx_errno,
                          "autocert: \"%s\" is not a directory", dir);
            return NGX_ERROR;
        }
    }
    return NGX_OK;
}


/*
 * M3/M5: ensure the per-CA account dir <path>/accounts/<ca_hash>/ exists (0700)
 * and migrate the legacy flat <path>/account.key into it ONCE (rename only if
 * the new key is absent and the old one is present). `ca` is the ca_list entry
 * this engine drives. Returns the per-CA key path (aliases the config-pool
 * string ca->account_key_path), or NULL on a hard failure.
 *
 * M5: the legacy-flat migration only makes sense for the PRIMARY CA (the one a
 * single-CA deploy used). `migrate` gates it so the second+ CA never tries to
 * rename the one shared flat key into its own dir (it would migrate to the wrong
 * CA's account dir, or — once the primary already took it — find it absent and
 * silently generate a fresh per-CA key, which is the correct behavior anyway).
 */
static u_char *
ngx_autocert_prepare_account_key(ngx_cycle_t *cycle, ngx_autocert_conf_t *acf,
    ngx_autocert_ca_entry_t *ca, ngx_uint_t migrate, ngx_pool_t *pool)
{
    u_char                   *accounts_dir, *ca_dir, *key_path, *old_flat, *p;
    size_t                    alen;
    struct stat               st;

    key_path = ca->account_key_path.data;       /* config pool; outlives worker */

    /* <path>/accounts (NUL-terminated) */
    alen = acf->path.len + sizeof("/accounts") - 1;
    accounts_dir = ngx_pnalloc(pool, alen + 1);
    if (accounts_dir == NULL) {
        return NULL;
    }
    p = ngx_cpymem(accounts_dir, acf->path.data, acf->path.len);
    p = ngx_cpymem(p, "/accounts", sizeof("/accounts") - 1);
    *p = '\0';

    /* <path>/accounts/<ca_hash> (NUL-terminated) */
    ca_dir = ngx_pnalloc(pool, alen + 1 + 8 + 1);
    if (ca_dir == NULL) {
        return NULL;
    }
    p = ngx_cpymem(ca_dir, accounts_dir, alen);
    *p++ = '/';
    p = ngx_cpymem(p, ca->ca_hash, 8);
    *p = '\0';

    if (ngx_autocert_mkdir_secure(cycle, accounts_dir) != NGX_OK
        || ngx_autocert_mkdir_secure(cycle, ca_dir) != NGX_OK)
    {
        return NULL;
    }

    /* One-time migration of the legacy flat key — PRIMARY CA only (M5). A
     * single-CA deploy's flat <path>/account.key belongs to the first CA; a
     * second CA must not claim it. */
    if (!migrate) {
        return key_path;
    }

    old_flat = ngx_pnalloc(pool, acf->path.len + sizeof("/account.key"));
    if (old_flat == NULL) {
        return NULL;
    }
    p = ngx_cpymem(old_flat, acf->path.data, acf->path.len);
    ngx_memcpy(p, "/account.key", sizeof("/account.key"));

    if (stat((char *) key_path, &st) == -1) {
        if (ngx_errno != NGX_ENOENT) {
            /* unknown stat error — do NOT treat as "absent" and migrate over it */
            ngx_log_error(NGX_LOG_WARN, cycle->log, ngx_errno,
                          "autocert: stat(\"%s\") failed; skipping account-key "
                          "migration", key_path);

        } else if (stat((char *) old_flat, &st) == 0) {
            /* new key absent + legacy key present: migrate atomically, once. */
            if (ngx_autocert_rename_noreplace(old_flat, key_path) == NGX_OK) {
                ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0,
                              "autocert: migrated account key \"%s\" -> \"%s\"",
                              old_flat, key_path);

            } else if (ngx_errno == NGX_EEXIST) {
                /* a key raced into the destination — already migrated; fine */

            } else {
                /* non-fatal: a fresh per-CA key is generated at key_path */
                ngx_log_error(NGX_LOG_WARN, cycle->log, ngx_errno,
                              "autocert: account key migration rename failed "
                              "(\"%s\" -> \"%s\")", old_flat, key_path);
            }
        }
    }

    return key_path;
}


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
    ngx_autocert_conf_t       acf;

    if (ngx_quit || ngx_terminate || ngx_exiting) {
        return;
    }

    if (ngx_autocert_get_conf(cycle, &acf) != NGX_OK || !acf.configured) {
        ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0,
                      "autocert: no http{} autocert config; driver idle");
        return;
    }

    ngx_log_debug3(NGX_LOG_DEBUG_CORE, cycle->log, 0,
                   "autocert: kick config CAs:%ui names:%ui challenge:%ui",
                   acf.ca_list ? acf.ca_list->nelts : 0,
                   acf.names ? acf.names->nelts : 0,
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

    /*
     * M4 (Codex #4) / M5: no issuable names => nothing to order, so do NOT build
     * any ACME client or bootstrap any account. With per-vhost multi-CA an empty
     * ca_list means no enabled vhost groups under any CA. The test seeds above
     * are intentionally exempt (they exercise the serve path without an order
     * flow). The renewal scheduler already guards on names; this guards the
     * account bootstrap on the same condition.
     */
    if (acf.names == NULL || acf.names->nelts == 0
        || acf.ca_list == NULL || acf.ca_list->nelts == 0)
    {
        ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0,
                      "autocert: no issuable names; driver idle (no account)");
        return;
    }

    /* Build the per-CA engine array once (idempotent across kick retries). */
    if (ngx_autocert_ca_states == NULL) {
        ngx_autocert_ca_entry_t  *entries = acf.ca_list->elts;
        ngx_uint_t                n = acf.ca_list->nelts;
        ngx_uint_t                i;

        if (n > NGX_MAX_SIZE_T_VALUE / sizeof(ngx_autocert_ca_state_t)) {
            ngx_log_error(NGX_LOG_ERR, cycle->log, 0,
                          "autocert: implausible CA count");
            return;
        }

        ngx_autocert_ca_states = ngx_pcalloc(cycle->pool,
            n * sizeof(ngx_autocert_ca_state_t));
        if (ngx_autocert_ca_states == NULL) {
            ngx_add_timer(ev, NGX_AUTOCERT_KICK_RETRY);
            return;
        }
        for (i = 0; i < n; i++) {
            ngx_autocert_ca_states[i].entry = &entries[i];
        }
        ngx_autocert_ca_states_n = n;
        ngx_autocert_cycle = cycle;

        ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0,
                      "autocert: %ui CA engine(s) to bootstrap", n);
    }

    /* Kick the SEQUENTIAL account bootstrap from the first CA (idempotent: if
     * CA[0] is already live/in-flight, bootstrap_ca short-circuits). The chain
     * (account_done -> next CA -> ... -> arm scheduler) takes it from here. */
    ngx_autocert_bootstrap_ca(cycle, 0);
}


/*
 * M5: bootstrap (build client + register account) for one CA engine, then chain.
 * Skips a CA that is already live or already has an in-flight bootstrap. On a
 * transient failure to START this CA's bootstrap, SKIPS to the next CA (a single
 * bad CA must not wedge the others); the scheduler is armed once the chain
 * reaches the end with at least one live account, else the kick is re-armed.
 */
static void
ngx_autocert_bootstrap_ca(ngx_cycle_t *cycle, ngx_uint_t ca_idx)
{
    ngx_autocert_conf_t       acf;
    ngx_autocert_ca_state_t  *state;
    ngx_autocert_account_t   *acct;
    ngx_pool_t               *pool;
    ngx_uint_t                i, any_live, any_dead;

    if (ngx_quit || ngx_terminate || ngx_exiting) {
        return;
    }

    if (ngx_autocert_get_conf(cycle, &acf) != NGX_OK || !acf.configured) {
        return;
    }

    while (ca_idx < ngx_autocert_ca_states_n) {
        state = &ngx_autocert_ca_states[ca_idx];

        /* Already live, or bootstrap already in flight: move past it. */
        if (state->account != NULL) {
            ca_idx++;
            continue;
        }

        /* Build this CA's outbound client lazily. */
        if (!state->client_ready) {
            if (ngx_autocert_acme_client_create(&state->client, cycle,
                    &state->entry->ca_conf.ca_certificate, acf.resolver,
                    NGX_AUTOCERT_HTTP_TIMEOUT)
                != NGX_OK)
            {
                ngx_log_error(NGX_LOG_ERR, cycle->log, 0,
                              "autocert: failed to build ACME client for %V; "
                              "skipping this CA", &state->entry->ca_conf.ca);
                ca_idx++;
                continue;
            }
            state->client.resolver_timeout = acf.resolver_timeout * 1000;
            state->client_ready = 1;
        }

        pool = ngx_create_pool(NGX_MIN_POOL_SIZE, cycle->log);
        if (pool == NULL) {
            ca_idx++;
            continue;
        }

        acct = ngx_pcalloc(pool, sizeof(ngx_autocert_account_t));
        if (acct == NULL) {
            ngx_destroy_pool(pool);
            ca_idx++;
            continue;
        }

        acct->client = &state->client;
        acct->cycle = cycle;
        acct->log = cycle->log;
        acct->directory_url = state->entry->ca_conf.ca;
        acct->key_type = acf.key_type;
        /* Per-CA contact: this CA group's own email, or the legacy first-overall
         * email if the group set none. */
        acct->email = state->entry->email.len ? state->entry->email : acf.email;
        acct->eab_kid = state->entry->ca_conf.eab_kid;
        acct->eab_hmac_key = state->entry->ca_conf.eab_hmac_key;
        acct->handler = ngx_autocert_account_done;
        acct->data = state;             /* chain key: which CA engine this is */

        /* M3/M5: per-CA account key <path>/accounts/<ca_hash>/account.key. Only
         * the first CA (ca_idx 0) migrates the legacy flat key into its dir. */
        acct->key_path.data = ngx_autocert_prepare_account_key(cycle, &acf,
                                  state->entry, ca_idx == 0, pool);
        if (acct->key_path.data == NULL) {
            ngx_destroy_pool(pool);
            ca_idx++;
            continue;
        }
        acct->key_path.len = ngx_strlen(acct->key_path.data);

        state->account = acct;
        state->account_pool = pool;

        ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0,
                      "autocert: registering ACME account via %V",
                      &state->entry->ca_conf.ca);

        if (ngx_autocert_account_register(acct) != NGX_OK) {
            ngx_log_error(NGX_LOG_ERR, cycle->log, 0,
                          "autocert: could not start ACME account registration "
                          "for %V; skipping this CA", &state->entry->ca_conf.ca);
            ngx_destroy_pool(pool);
            state->account = NULL;
            state->account_pool = NULL;
            ca_idx++;
            continue;
        }

        /* Registration started; its terminal (account_done) resumes the chain. */
        return;
    }

    /*
     * Chain reached the end. Arm the renewal scheduler if at least one account
     * came up. Independently, if ANY CA is still dead (transient client-build /
     * OOM / register-start / registration failure), re-arm the kick timer so the
     * dead CA(s) are retried — even when the scheduler is already armed for the
     * live ones (Codex M5 MED: a transient failure for one CA must not be
     * permanent just because another CA succeeded). The retry re-enters
     * bootstrap_ca(0): live accounts short-circuit, and start_order() /
     * sched arming are both idempotent.
     */
    any_live = 0;
    any_dead = 0;
    for (i = 0; i < ngx_autocert_ca_states_n; i++) {
        if (ngx_autocert_ca_states[i].account_live) {
            any_live = 1;
        } else {
            any_dead = 1;
        }
    }

    if (any_live) {
        ngx_autocert_start_order(cycle);
    }

    if (any_dead && !ngx_quit && !ngx_terminate && !ngx_exiting
        && ngx_autocert_kick_timer.handler != NULL
        && !ngx_autocert_kick_timer.timer_set)
    {
        ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0,
                      "autocert: %s; retrying bootstrap for the dead CA(s)",
                      any_live ? "some ACME accounts did not come up"
                               : "no ACME account came up");
        ngx_add_timer(&ngx_autocert_kick_timer, NGX_AUTOCERT_KICK_RETRY);
    }
}


/*
 * Terminal callback of a CA's account bootstrap (M5: data == that CA's engine
 * state). On failure the account is freed and the CA is left dead (account_live
 * stays 0). On success the account is kept ALIVE as the ACME session for that CA
 * (it owns the kid, key and current nonce that every later kid-signed POST is
 * signed with). Either way the SEQUENTIAL bootstrap chain resumes at the NEXT CA
 * (bootstrap_ca), which arms the renewal scheduler once the last CA is handled
 * with >=1 live account. The CI asserts on the success line emitted by the
 * account module.
 */
static void
ngx_autocert_account_done(ngx_autocert_account_t *acct, ngx_int_t rc)
{
    ngx_autocert_ca_state_t  *state = acct->data;
    ngx_cycle_t              *cycle = ngx_autocert_cycle;
    ngx_uint_t                next;

    /* Recover this CA's index to resume the chain at the next one. */
    next = (ngx_uint_t) (state - ngx_autocert_ca_states) + 1;

    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, acct->log, 0,
                      "autocert: ACME account registration failed for %V",
                      &state->entry->ca_conf.ca);
        ngx_autocert_account_free(acct);            /* key + bootstrap pool */
        state->account = NULL;
        if (state->account_pool) {
            ngx_destroy_pool(state->account_pool);
            state->account_pool = NULL;
        }
        /* Leave this CA dead; the chain continues with the rest. */
        ngx_autocert_bootstrap_ca(cycle, next);
        return;
    }

    state->account_live = 1;
    ngx_log_debug1(NGX_LOG_DEBUG_CORE, acct->log, 0,
                   "autocert: ACME account ready, kid \"%V\"", &acct->kid);

    /* Account kept alive; resume the bootstrap chain at the next CA (the last
     * CA arms the renewal scheduler in bootstrap_ca). */
    ngx_autocert_bootstrap_ca(cycle, next);
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
 * every sweep. A success clears it. (ngx_autocert_backoff_t is defined near the
 * top; each CA engine owns its own per-name array in ngx_autocert_ca_state_t.)
 */
#define NGX_AUTOCERT_BACKOFF_BASE    60          /* 60s first retry hold */
#define NGX_AUTOCERT_BACKOFF_MAXSHIFT 6          /* 60s..3840s growth */
#define NGX_AUTOCERT_BACKOFF_CAP     (60 * 60)   /* 1h ceiling, seconds */

static ngx_event_t              ngx_autocert_sched_timer;
static ngx_uint_t               ngx_autocert_sched_ca;     /* next CA to scan */
static ngx_uint_t               ngx_autocert_sched_index;  /* next name in that CA */
static ngx_uint_t               ngx_autocert_sched_cur_ca; /* CA index in flight */
static ngx_uint_t               ngx_autocert_sched_cur;    /* name index in flight */

static void ngx_autocert_sched_handler(ngx_event_t *ev);
static void ngx_autocert_sched_pump(ngx_cycle_t *cycle);
static ngx_int_t ngx_autocert_name_due(ngx_cycle_t *cycle,
    ngx_autocert_conf_t *acf, ngx_str_t *name);
static ngx_int_t ngx_autocert_start_order_for(ngx_cycle_t *cycle,
    ngx_autocert_conf_t *acf, ngx_autocert_ca_state_t *state, ngx_str_t *name);
static ngx_int_t ngx_autocert_ca_backoff_ensure(ngx_cycle_t *cycle,
    ngx_autocert_ca_state_t *state);
static void ngx_autocert_backoff_record(ngx_autocert_ca_state_t *state,
    ngx_uint_t index, ngx_uint_t success);
static void ngx_autocert_backoff_hold(ngx_autocert_ca_state_t *state,
    ngx_uint_t index, time_t when);


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

    if (ngx_quit || ngx_terminate || ngx_exiting) {
        return;                         /* retiring worker: don't start a sweep */
    }

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
    ngx_autocert_sched_ca = 0;
    ngx_autocert_sched_index = 0;
    ngx_autocert_sched_pump(cycle);
}


/*
 * M5: lazily size a CA engine's per-name backoff array to its name count.
 * Allocated from the cycle pool; the name set is stable for the worker's life
 * (a reload spawns fresh workers), so a realloc-on-mismatch is enough. Returns
 * NGX_OK with state->backoff valid, or NGX_ERROR (skip this CA this sweep).
 */
static ngx_int_t
ngx_autocert_ca_backoff_ensure(ngx_cycle_t *cycle,
    ngx_autocert_ca_state_t *state)
{
    ngx_uint_t  n;

    n = (state->entry->names != NULL) ? state->entry->names->nelts : 0;

    if (n == 0) {
        return NGX_ERROR;
    }

    if (state->backoff != NULL && state->backoff_n == n) {
        return NGX_OK;
    }

    /* Guard the size multiply against wrap (nelts is operator-controlled). */
    if (n > NGX_MAX_SIZE_T_VALUE / sizeof(ngx_autocert_backoff_t)) {
        ngx_log_error(NGX_LOG_ERR, cycle->log, 0,
                      "autocert: implausible server name count");
        state->backoff_n = 0;
        return NGX_ERROR;
    }

    state->backoff = ngx_pcalloc(cycle->pool,
                                 n * sizeof(ngx_autocert_backoff_t));
    if (state->backoff == NULL) {
        state->backoff_n = 0;
        return NGX_ERROR;
    }
    state->backoff_n = n;
    return NGX_OK;
}


/*
 * Advance the (CA, name) cursor from (sched_ca, sched_index), launching an order
 * for the first due name under a live CA engine. One order in flight across all
 * CAs. If the whole CAs×names space is exhausted with nothing to do, rearm the
 * periodic timer.
 */
static void
ngx_autocert_sched_pump(ngx_cycle_t *cycle)
{
    ngx_autocert_conf_t       acf;
    ngx_autocert_ca_state_t  *state;
    ngx_str_t                *names, *name;

    ngx_memzero(&acf, sizeof(ngx_autocert_conf_t));

    /* Don't launch new orders once the worker is retiring (Codex M5 MED): a
     * graceful QUIT must let the order in flight finish and then STOP — pumping
     * the next due name here would keep issuing and pin the singleton lock open,
     * blocking the next generation's worker 0 from taking over. The sched timer
     * is cancelable, so simply not rearming lets the worker exit promptly. */
    if (ngx_quit || ngx_terminate || ngx_exiting) {
        ngx_log_debug0(NGX_LOG_DEBUG_CORE, cycle->log, 0,
                       "autocert: worker exiting; scheduler pump stops");
        return;
    }

    if (ngx_autocert_order != NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_CORE, cycle->log, 0,
                       "autocert: scheduler pump paused, order in flight");
        return;                         /* one order at a time */
    }

    if (ngx_autocert_get_conf(cycle, &acf) != NGX_OK || !acf.configured) {
        goto rearm;
    }
    if (acf.challenge_zone == NULL) {
        ngx_log_error(NGX_LOG_ERR, cycle->log, 0,
                      "autocert: no challenge zone; cannot run order");
        goto rearm;
    }

    /* Outer cursor: CA engine. Inner cursor: name within that CA. */
    for ( ; ngx_autocert_sched_ca < ngx_autocert_ca_states_n;
         ngx_autocert_sched_ca++, ngx_autocert_sched_index = 0)
    {
        state = &ngx_autocert_ca_states[ngx_autocert_sched_ca];

        /* A CA whose account never came up is skipped (its names can't issue). */
        if (!state->account_live || state->account == NULL) {
            continue;
        }
        if (state->entry->names == NULL || state->entry->names->nelts == 0) {
            continue;
        }
        if (ngx_autocert_ca_backoff_ensure(cycle, state) != NGX_OK) {
            continue;
        }

        names = state->entry->names->elts;

        while (ngx_autocert_sched_index < state->entry->names->nelts) {
            ngx_uint_t  i = ngx_autocert_sched_index++;

            name = &names[i];

            /* Honour the per-name failure backoff before any disk/clock check. */
            if (state->backoff[i].next_eligible > ngx_time()) {
                ngx_log_debug2(NGX_LOG_DEBUG_CORE, cycle->log, 0,
                               "autocert: name \"%V\" held by backoff until %T",
                               name, state->backoff[i].next_eligible);
                continue;
            }

            if (!ngx_autocert_name_due(cycle, &acf, name)) {
                ngx_log_debug1(NGX_LOG_DEBUG_CORE, cycle->log, 0,
                               "autocert: name \"%V\" not due", name);
                continue;
            }

            ngx_autocert_sched_cur_ca = ngx_autocert_sched_ca;
            ngx_autocert_sched_cur = i;     /* (CA, name) in flight */

            if (ngx_autocert_start_order_for(cycle, &acf, state, name)
                == NGX_OK)
            {
                return;                 /* order_complete will pump again */
            }
            /* Launch failed (transient: pool/OOM) — treat as a failure for the
             * backoff so we don't spin on it, then try the next name. */
            ngx_autocert_backoff_record(state, i, 0);
        }
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
        ngx_uint_t  c, i;

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

        /* If any name under any CA is backing off, wake when the soonest hold
         * expires (so a 60s backoff isn't stuck behind a 12h sweep). */
        for (c = 0; c < ngx_autocert_ca_states_n; c++) {
            ngx_autocert_ca_state_t  *s = &ngx_autocert_ca_states[c];
            for (i = 0; i < s->backoff_n; i++) {
                time_t  e = s->backoff[i].next_eligible;
                if (e > now && (soonest == 0 || e < soonest)) {
                    soonest = e;
                }
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
ngx_autocert_backoff_record(ngx_autocert_ca_state_t *state, ngx_uint_t index,
    ngx_uint_t success)
{
    ngx_autocert_backoff_t  *b;
    ngx_uint_t               shift;
    time_t                   delay;

    if (state->backoff == NULL || index >= state->backoff_n) {
        return;
    }

    b = &state->backoff[index];

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
ngx_autocert_backoff_hold(ngx_autocert_ca_state_t *state, ngx_uint_t index,
    time_t when)
{
    ngx_autocert_backoff_t  *b;

    if (state->backoff == NULL || index >= state->backoff_n) {
        return;
    }

    b = &state->backoff[index];
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
    ngx_str_t   seg;
    u_char      seg_buf[NGX_AUTOCERT_DOMAIN_SEG_MAX];

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

    /* D4: a wildcard name "*.rest" is stored under "_wildcard_.rest"; map to the
     * same fs segment the store writer + serve path use so the freshness check
     * stats the file that was actually written (else it would look perpetually
     * un-issued and reorder every sweep). */
    seg.data = seg_buf;
    seg.len = ngx_autocert_fs_segment(seg_buf, sizeof(seg_buf), name);
    if (seg.len == 0) {
        ngx_log_error(NGX_LOG_ERR, cycle->log, 0,
                      "autocert: store segment too long for \"%V\"", name);
        return 0;
    }

    base = acf->path.len + (certbot ? sizeof("/live") - 1 : 0)
           + 1 + seg.len + sizeof("/fullchain.pem");
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
    p = ngx_cpymem(p, seg.data, seg.len);
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
 * Launch the M6a/M6b order flow for one name under a given CA engine, reusing
 * that CA's live account as the ACME session and its directory URL. Returns
 * NGX_OK if the order started (ngx_autocert_order set); NGX_ERROR otherwise
 * (caller moves on to the next name). EAB is on the account (set at register),
 * so the order needs none.
 */
static ngx_int_t
ngx_autocert_start_order_for(ngx_cycle_t *cycle, ngx_autocert_conf_t *acf,
    ngx_autocert_ca_state_t *state, ngx_str_t *name)
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
    order->account = state->account;
    order->log = cycle->log;
    order->directory_url = state->entry->ca_conf.ca;
    order->domain = *name;
    order->challenge_zone = acf->challenge_zone;
    order->challenge = acf->challenge;          /* M10c/M16: http/alpn/dns */
    order->alpn_zone = acf->alpn_zone;          /* M10b store, used when alpn */
    order->dns_hook_add = acf->dns_hook_add;            /* M16 dns-01 */
    order->dns_hook_remove = acf->dns_hook_remove;
    order->dns_propagation_delay = acf->dns_propagation_delay;
    order->dns_hook_timeout = acf->dns_hook_timeout;
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
    ngx_cycle_t              *cycle = order->data;
    ngx_autocert_ca_state_t  *state;

    if (rc == NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, order->log, 0,
                      "autocert: certificate provisioned for \"%V\"",
                      &order->domain);
    } else {
        ngx_log_error(NGX_LOG_ERR, order->log, 0,
                      "autocert: ACME order failed for \"%V\"", &order->domain);
    }

    /* The in-flight (CA, name) was recorded at launch. Record the outcome into
     * THAT CA's per-name backoff: success clears it, failure grows the per-name
     * retry delay (don't hammer a failing name). */
    state = &ngx_autocert_ca_states[ngx_autocert_sched_cur_ca];

    ngx_autocert_backoff_record(state, ngx_autocert_sched_cur, rc == NGX_OK);

    /* If the CA rate-limited us (429), honour its Retry-After: hold this name
     * at least until then, on top of the exponential backoff just recorded. */
    if (rc != NGX_OK && order->retry_after > 0) {
        ngx_autocert_backoff_hold(state, ngx_autocert_sched_cur,
                                  order->retry_after);
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

    /*
     * Ensure the store directory exists before we put the lock file (and later
     * the account key + certs) in it. The old root helper relied on the dir
     * pre-existing; the worker driver creates it (idempotent, EEXIST is fine) so
     * a fresh deploy with a not-yet-created autocert_path works out of the box.
     * ngx_create_full_path makes intermediate components too. 0700: only the
     * worker user needs it (it holds private keys).
     */
    ngx_memcpy(path, acf.path.data, acf.path.len);
    path[acf.path.len] = '\0';

    if (ngx_create_dir(path, 0700) == NGX_FILE_ERROR) {
        ngx_err_t  err = ngx_errno;

        if (err == NGX_ENOENT) {
            /* A parent component is missing — create the whole chain (this makes
             * the intermediates; ngx_create_full_path stops at the last '/', so
             * retry the leaf mkdir afterwards). */
            ngx_err_t  ferr = ngx_create_full_path(path, 0700);
            if (ferr != 0 && ferr != NGX_EEXIST) {
                ngx_log_error(NGX_LOG_ERR, cycle->log, ferr,
                              "autocert: cannot create store path \"%s\"", path);
                return NGX_ERROR;
            }
            if (ngx_create_dir(path, 0700) == NGX_FILE_ERROR
                && ngx_errno != NGX_EEXIST)
            {
                ngx_log_error(NGX_LOG_ERR, cycle->log, ngx_errno,
                              "autocert: cannot create store dir \"%s\"", path);
                return NGX_ERROR;
            }

        } else if (err != NGX_EEXIST) {
            ngx_log_error(NGX_LOG_ERR, cycle->log, err,
                          "autocert: cannot create store dir \"%s\"", path);
            return NGX_ERROR;
        }
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

    ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0,
                  "autocert: acquired driver lock, pid %P", ngx_pid);

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

    /* M5: tear down every per-CA engine (account + bootstrap pool + client). */
    if (ngx_autocert_ca_states != NULL) {
        ngx_uint_t  i;

        for (i = 0; i < ngx_autocert_ca_states_n; i++) {
            ngx_autocert_ca_state_t  *state = &ngx_autocert_ca_states[i];

            if (state->account != NULL) {
                ngx_autocert_account_free(state->account);
                state->account = NULL;
            }
            if (state->account_pool != NULL) {
                ngx_destroy_pool(state->account_pool);
                state->account_pool = NULL;
            }
            if (state->client_ready) {
                ngx_autocert_acme_client_destroy(&state->client);
                state->client_ready = 0;
            }
        }
        /* ca_states itself is in the cycle pool; nginx frees it. */
        ngx_autocert_ca_states = NULL;
        ngx_autocert_ca_states_n = 0;
    }

    /* Release the singleton lock (kernel drops it on close) so the next
     * generation's worker 0 can take over immediately. */
    if (ngx_autocert_lock_fd != -1) {
        (void) close(ngx_autocert_lock_fd);
        ngx_autocert_lock_fd = -1;
        ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0,
                      "autocert: released driver lock, pid %P", ngx_pid);
    }
}


/*
 * `master_process off` reload. In single-process mode the same process survives
 * a SIGHUP: ngx_single_process_cycle() runs ngx_init_cycle() (which re-reads the
 * config and re-runs every module's init_module) but never calls exit_process /
 * init_process again. Without this, the driver keeps timers, per-CA engines, the
 * in-flight order, and the test-seed latches all bound to the dead cycle and its
 * pool, so a reload silently ignores new autocert config and can touch freed
 * cycle memory. init_module calls this on the single-process path to tear the
 * engine state down and re-arm it against the NEW cycle. The interprocess lock
 * is intentionally kept open: this process is still the sole driver, so there is
 * no peer to hand it to and re-flock'ing would only add a failure mode.
 *
 * Must run inside the worker event loop (true on reload — init_module fires from
 * ngx_init_cycle() while the loop is live), since it re-arms a timer.
 */
void
ngx_autocert_driver_reload(ngx_cycle_t *cycle)
{
    /* Cancel every driver timer bound to the old cycle. The handlers carry the
     * old cycle in ev->data, so they must not fire after the cycle is gone. */
    if (ngx_autocert_kick_timer.timer_set) {
        ngx_del_timer(&ngx_autocert_kick_timer);
    }
    if (ngx_autocert_sched_timer.timer_set) {
        ngx_del_timer(&ngx_autocert_sched_timer);
    }
    if (ngx_autocert_relock_timer.timer_set) {
        ngx_del_timer(&ngx_autocert_relock_timer);
    }

    /* Detach any pending ACME resolver/socket event BEFORE freeing the pools its
     * request lives in: the process keeps running across this reload, so a live
     * event would otherwise fire on freed memory (and its handler would touch the
     * dead-cycle driver state we are about to drop). */
    ngx_autocert_acme_cancel_inflight();

    /* Drop the in-flight order (its pool is independent of the cycle pool). */
    if (ngx_autocert_order != NULL) {
        ngx_autocert_order_free(ngx_autocert_order);
        ngx_autocert_order = NULL;
    }
    if (ngx_autocert_order_pool != NULL) {
        ngx_destroy_pool(ngx_autocert_order_pool);
        ngx_autocert_order_pool = NULL;
    }

    /* Tear down every per-CA engine. ca_states itself was allocated from the OLD
     * cycle pool (freed by ngx_clean_old_cycles once the old cycle retires), so
     * just drop the pointer — the kick rebuilds it from the new cycle's ca_list. */
    if (ngx_autocert_ca_states != NULL) {
        ngx_uint_t  i;

        for (i = 0; i < ngx_autocert_ca_states_n; i++) {
            ngx_autocert_ca_state_t  *state = &ngx_autocert_ca_states[i];

            if (state->account != NULL) {
                ngx_autocert_account_free(state->account);
                state->account = NULL;
            }
            if (state->account_pool != NULL) {
                ngx_destroy_pool(state->account_pool);
                state->account_pool = NULL;
            }
            if (state->client_ready) {
                ngx_autocert_acme_client_destroy(&state->client);
                state->client_ready = 0;
            }
        }
        ngx_autocert_ca_states = NULL;
        ngx_autocert_ca_states_n = 0;
    }

    /* Reset the scheduler cursor and the one-shot test-seed latches so the new
     * config is scanned and (re)seeded from scratch. */
    ngx_autocert_sched_ca = 0;
    ngx_autocert_sched_index = 0;
    ngx_autocert_sched_cur_ca = 0;
    ngx_autocert_sched_cur = 0;
    ngx_memzero(&ngx_autocert_sched_timer, sizeof(ngx_event_t));
    ngx_autocert_test_seeded = 0;
    ngx_autocert_test_alpn_seeded = 0;

    ngx_autocert_cycle = cycle;

    /*
     * Release the old lock and re-acquire from scratch. The lock file lives in
     * the store dir, so a reload that changes autocert_path (or disables autocert
     * entirely) would otherwise leave us holding the OLD store's lock while the
     * new store runs unlocked. Closing here + going back through init_process
     * makes trylock() derive the lock path from the NEW cycle's config: it
     * re-locks the same path when unchanged, moves to the new path when changed,
     * and stays unlocked (idle) when the new config has no issuable names. */
    if (ngx_autocert_lock_fd != -1) {
        (void) close(ngx_autocert_lock_fd);
        ngx_autocert_lock_fd = -1;
    }

    ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0,
                  "autocert: reload (master_process off) — re-arming driver "
                  "against new cycle, pid %P", ngx_pid);

    ngx_autocert_driver_init_process(cycle);
}
