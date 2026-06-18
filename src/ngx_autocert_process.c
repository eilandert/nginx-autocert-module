/*
 * ngx_autocert_process — the dedicated ACME helper process (M4a).
 *
 * The master spawns ONE long-lived helper that runs nginx's own event loop and
 * is driven entirely over the master<->child channel socketpair. This is the
 * privilege-separated process that, from later milestones, holds the ACME
 * account key and the certificate private keys; workers never see them.
 *
 * Design (replaces the M1 DETACHED + pidfile-watch stand-in):
 *
 *   - Spawn type RESPAWN (first start) / JUST_RESPAWN (every reload). Both set
 *     respawn=1, so ngx_reap_children() restarts the helper automatically if it
 *     crashes -- no manual liveness check is needed. JUST_RESPAWN marks the
 *     freshly spawned helper with just_spawn=1 so the QUIT sweep that follows a
 *     reload skips it, while the previous-generation helper (just_spawn=0) is
 *     told NGX_CMD_QUIT over its channel and reaped. This mirrors exactly how
 *     nginx restarts its own workers and the cache manager across a reload.
 *
 *   - The helper runs ngx_process_events_and_timers() and reacts to ngx_quit /
 *     ngx_terminate / ngx_reopen, which are set either by a direct signal
 *     (inherited handlers) or by the master writing NGX_CMD_QUIT / TERMINATE /
 *     REOPEN over the channel. We register the channel with ngx_add_channel_event
 *     and read it with our own handler (nginx's ngx_channel_handler is static).
 *
 * The spawn happens from a CORE module's init_module(), which runs in the
 * master during ngx_init_cycle() on startup AND on every reload -- the same
 * master, in place. ngx_spawn_process / ngx_add_channel_event are exported to
 * dynamic modules under --with-compat; ngx_worker_process_init() is static, so
 * the helper does its own minimal process init below.
 *
 * The ACME event loop / outbound client lands from M4b onward; M4a only proves
 * the process exists with a real event loop, logs a heartbeat, survives reloads
 * and crashes, and tears down cleanly.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_channel.h>

#include "ngx_autocert_shared.h"
#include "ngx_autocert_acme.h"
#include "ngx_autocert_account.h"
#include "ngx_autocert_challenge.h"
#include "ngx_autocert_order.h"


#define NGX_AUTOCERT_PROC_NAME    "autocert helper"
#define NGX_AUTOCERT_HEARTBEAT    60000   /* ms; placeholder until M4b */
#define NGX_AUTOCERT_WATCH        1000    /* ms; master-liveness poll */
#define NGX_AUTOCERT_STARTUP_BUDGET 30000 /* ms; give up if master never seen */
#define NGX_AUTOCERT_KICK         500     /* ms; defer first ACME fetch */
#define NGX_AUTOCERT_HTTP_TIMEOUT 30000   /* ms; per-request transport timeout */


static ngx_int_t ngx_autocert_process_init_module(ngx_cycle_t *cycle);
static void ngx_autocert_process_cycle(ngx_cycle_t *cycle, void *data);
static void ngx_autocert_channel_handler(ngx_event_t *ev);
static void ngx_autocert_heartbeat_handler(ngx_event_t *ev);
static void ngx_autocert_watch_handler(ngx_event_t *ev);
static ngx_uint_t ngx_autocert_master_gone(ngx_cycle_t *cycle);
static void ngx_autocert_close_listening(ngx_cycle_t *cycle);
static void ngx_autocert_kick_handler(ngx_event_t *ev);
static void ngx_autocert_account_done(ngx_autocert_account_t *acct,
    ngx_int_t rc);
static void ngx_autocert_start_order(ngx_cycle_t *cycle);
static void ngx_autocert_order_complete(ngx_autocert_order_t *order,
    ngx_int_t rc);


/*
 * The outbound ACME client, owned by the helper for its lifetime, built once
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


static ngx_core_module_t  ngx_autocert_process_module_ctx = {
    ngx_string("autocert_process"),
    NULL,                                  /* create_conf */
    NULL                                   /* init_conf */
};


ngx_module_t  ngx_autocert_process_module = {
    NGX_MODULE_V1,
    &ngx_autocert_process_module_ctx,      /* module context */
    NULL,                                  /* module directives */
    NGX_CORE_MODULE,                       /* module type */
    NULL,                                  /* init master */
    ngx_autocert_process_init_module,      /* init module (master context) */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


/*
 * Cleared on the very first init_module() call of this master's lifetime, set
 * thereafter. Distinguishes a cold start (RESPAWN) from a reload (JUST_RESPAWN);
 * a reload re-runs ngx_init_cycle() in the same master, so the static persists.
 */
static ngx_uint_t  ngx_autocert_started;

/*
 * Slot index of the detached cold-start orphan in ngx_processes[], or -1 if the
 * tracked helper is channel-managed. Only the detached cold helper must be
 * retired explicitly on the next reload (the QUIT sweep skips detached slots),
 * and it is retired by WRITING NGX_CMD_QUIT to its channel[0] -- targeting the
 * fd, not the pid, so a dead+reused pid can never be signalled. Channel-managed
 * helpers are retired by nginx's own reconfigure QUIT sweep.
 */
static ngx_int_t  ngx_autocert_cold_slot = -1;


/*
 * init_module runs in the master during ngx_init_cycle(), on startup AND on
 * every reload. Spawn the helper each time, matching how nginx (re)starts its
 * workers: on reload the new helper is JUST_RESPAWN (skipped by the immediately
 * following QUIT sweep), the old one is QUIT and reaped.
 *
 * Skipped for `nginx -t`/`-T` (config test) and for signaller runs
 * (`-s reload/stop/...`), which build a cycle but must not fork a daemon.
 */
static ngx_int_t
ngx_autocert_process_init_module(ngx_cycle_t *cycle)
{
    ngx_pid_t         pid;
    ngx_int_t         type;
    ngx_uint_t        cold_orphan;
    ngx_core_conf_t  *ccf;

    if (ngx_test_config) {
        return NGX_OK;
    }

    if (ngx_process == NGX_PROCESS_SIGNALLER) {
        return NGX_OK;
    }

    /*
     * Only the real master spawns the helper. Single-process mode
     * (`master_process off`) has no worker sweep/reaper to drive a channel-
     * managed helper, and init_module there also runs pre-daemon; rather than
     * fake a lifecycle, skip it -- autocert is unsupported in single-process
     * mode for now (M4a). NGX_PROCESS_SINGLE is the value here both for genuine
     * single mode and on the pre-daemon master pass, so distinguish by ccf.
     */
    ccf = (ngx_core_conf_t *) ngx_get_conf(cycle->conf_ctx, ngx_core_module);

    if (!ccf->master) {
        if (!ngx_autocert_started) {
            ngx_log_error(NGX_LOG_WARN, cycle->log, 0,
                          "autocert: helper not started in single-process mode "
                          "(master_process off); certificate provisioning is "
                          "disabled");
            ngx_autocert_started = 1;       /* don't repeat the warning */
        }
        return NGX_OK;
    }

    if (ngx_process != NGX_PROCESS_MASTER
        && ngx_process != NGX_PROCESS_SINGLE)
    {
        return NGX_OK;                      /* not the master context */
    }

    /*
     * Cold start vs reload. init_module runs inside ngx_init_cycle():
     *   - reload: from ngx_master_process_cycle(), already daemonized, in the
     *     real master -> the helper is the master's child. Use JUST_RESPAWN so
     *     the reconfigure QUIT sweep skips the new helper while QUITing the old.
     *   - cold start that WILL daemonize: init_module runs from main() BEFORE
     *     ngx_daemon() forks the real master and the pre-daemon parent exits. A
     *     child spawned here is re-parented to init and is the master's SIBLING,
     *     not its child, so the master can never waitpid() it -- a plain RESPAWN
     *     slot would wedge shutdown. Mark it DETACHED (master neither waits on
     *     nor signals it) and have the helper watch the master itself.
     *   - cold start with `daemon off`: no fork, the master IS init_module's
     *     process -> the helper is a real child, keep it channel-managed.
     * The detached/orphan path is needed ONLY when nginx will actually fork
     * through ngx_daemon(): master mode, daemon on, not yet daemonized, and not
     * an inherited (hot-upgrade) start.
     */
    cold_orphan = ccf->daemon && !ngx_daemonized && !ngx_inherited;

    type = ngx_autocert_started ? NGX_PROCESS_JUST_RESPAWN
                                : NGX_PROCESS_RESPAWN;

    pid = ngx_spawn_process(cycle, ngx_autocert_process_cycle, NULL,
                            (char *) NGX_AUTOCERT_PROC_NAME, type);

    if (pid == NGX_INVALID_PID) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                      "autocert: failed to spawn helper process");
        /*
         * Non-fatal: the server must still start and serve traffic. Without the
         * helper, autocert simply won't provision certs (logged above).
         */
        return NGX_OK;
    }

    /*
     * Retire the previous COLD (detached) helper before recording the new one.
     * The reconfigure QUIT sweep skips detached slots, so a cold helper would
     * otherwise live forever and helpers would accumulate across reloads. We
     * retire it by writing NGX_CMD_QUIT to its channel[0] (targets the fd, not
     * the pid -> a dead+reused pid can never be hit), then close that fd and
     * free the slot so the master stops routing OPEN_CHANNEL fds to it.
     *
     * Channel-managed (non-detached) helpers are NOT touched here: nginx's own
     * QUIT sweep retires them, and nginx may have auto-respawned one to a new
     * pid/slot we don't track -- so we never reach into their slots.
     */
    if (ngx_autocert_cold_slot != -1) {
        ngx_int_t      s = ngx_autocert_cold_slot;
        ngx_pid_t      cpid = ngx_processes[s].pid;
        ngx_channel_t  ch;

        if (ngx_processes[s].channel[0] != -1) {
            ngx_memzero(&ch, sizeof(ngx_channel_t));
            ch.command = NGX_CMD_QUIT;
            ch.fd = -1;

            /*
             * The channel is nonblocking, so a full pipe returns NGX_AGAIN and
             * QUIT is NOT delivered. Once we close the fd below the master loses
             * its only handle on this detached helper, so guarantee delivery
             * with a fallback signal. cpid is still valid here (the helper is
             * not yet reaped), so the fd-target-vs-pid-reuse concern does not
             * apply to this in-the-moment fallback.
             */
            if (ngx_write_channel(ngx_processes[s].channel[0], &ch,
                                  sizeof(ngx_channel_t), cycle->log)
                != NGX_OK
                && cpid != NGX_INVALID_PID)
            {
                if (kill(cpid, ngx_signal_value(NGX_SHUTDOWN_SIGNAL)) == -1
                    && ngx_errno != NGX_ESRCH)
                {
                    ngx_log_error(NGX_LOG_WARN, cycle->log, ngx_errno,
                                  "autocert: fallback kill(%P, QUIT) to retire "
                                  "cold helper failed", cpid);
                }
            }

            if (close(ngx_processes[s].channel[0]) == -1) {
                ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                              "autocert: close() cold-helper channel failed");
            }
            ngx_processes[s].channel[0] = -1;
        }
        if (ngx_processes[s].channel[1] != -1) {
            (void) close(ngx_processes[s].channel[1]);
            ngx_processes[s].channel[1] = -1;
        }
        ngx_processes[s].pid = -1;       /* free the slot: no more fd routing */
        ngx_autocert_cold_slot = -1;
    }

    if (cold_orphan) {
        /*
         * ngx_spawn_process set ngx_process_slot to the new slot. Detach it in
         * the master's table: the post-daemon master skips detached children in
         * both the shutdown reap-liveness loop and the signal sweep, so it
         * neither hangs waiting for this orphan nor tries to signal it.
         *
         * Also clear respawn: this orphan is re-parented to init and is not the
         * master's child, so the master can neither waitpid() nor respawn it.
         * Leaving respawn=1 would be a lie (no auto-restart on crash); make the
         * slot honestly no-respawn. A cold-start helper crash before the first
         * reload therefore leaves no helper until the next reload -- a known
         * limitation of the pre-daemon spawn, tracked for the M4b control-pipe
         * rework. The helper self-watches the master so it never outlives it.
         */
        ngx_processes[ngx_process_slot].detached = 1;
        ngx_processes[ngx_process_slot].respawn = 0;
        ngx_autocert_cold_slot = ngx_process_slot;   /* retire via channel later */
    }

    ngx_autocert_started = 1;

    ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0,
                  "autocert: helper process spawned, pid %P", pid);

    return NGX_OK;
}


/*
 * The helper process body, forked from the master by ngx_spawn_process().
 * Minimal stand-in for the static ngx_worker_process_init(): unblock signals,
 * install nginx's signal handlers, drop the listening sockets, run each
 * module's init_process (so the event subsystem is set up), then register our
 * channel and loop on the event/timer engine until told to quit.
 *
 * Privilege note: unlike a worker, the helper deliberately keeps its inherited
 * (typically root) privileges -- from M4b+ it owns the ACME account and cert
 * private keys, which is the whole point of running it as a separate process.
 * So we do NOT setuid/setgid here.
 */
static void
ngx_autocert_process_cycle(ngx_cycle_t *cycle, void *data)
{
    ngx_int_t    n;
    ngx_uint_t   i;
    sigset_t     set;
    ngx_event_t  heartbeat;
    ngx_event_t  watch;
    ngx_event_t  kick;

    ngx_process = NGX_PROCESS_HELPER;

    /*
     * Point the global at our cycle. ngx_get_connection() (used by
     * ngx_add_channel_event) and other helpers read ngx_cycle, not the cycle
     * argument; in a normal worker ngx_worker_process_init() runs against the
     * same cycle ngx_cycle already names, but our spawn inherits the master's.
     */
    ngx_cycle = cycle;

    /*
     * Forked before the master finished installing its signal handlers on a
     * cold start, so the child may have inherited default dispositions (SIGQUIT
     * would core-dump, SIGUSR1/HUP would kill it). Install nginx's handlers in
     * the child first.
     */
    if (ngx_init_signals(cycle->log) != NGX_OK) {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, 0,
                      "autocert: ngx_init_signals() failed");
    }

    /*
     * The fork inherited every listening socket. The helper serves no traffic,
     * so close them all. ngx_close_listening_sockets() skips QUIC/UDP reuseport
     * listeners, so close the listen fds directly to avoid pinning those too --
     * and do the same for the old cycle on a reload, whose listeners were also
     * inherited and would otherwise keep removed addresses bound.
     */
    ngx_autocert_close_listening(cycle);
    if (cycle->old_cycle) {
        ngx_autocert_close_listening(cycle->old_cycle);
    }

    /* A helper needs only a handful of connections (channel + outbound ACME). */
    cycle->connection_n = 512;

    /*
     * ngx_spawn_process() forks with all signals BLOCKED (the master blocks
     * them before fork so it can install handlers race-free). Unblock them here
     * -- mirror ngx_worker_process_init()'s sigprocmask(SIG_SETMASK, empty) --
     * else this process never receives SIGQUIT/SIGTERM and the master SIGKILLs
     * it on shutdown.
     */
    sigemptyset(&set);
    if (sigprocmask(SIG_SETMASK, &set, NULL) == -1) {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                      "autocert: sigprocmask() failed");
    }

    /*
     * Bring up each module's init_process. For the active event module this
     * creates the connection/event slots and the event engine (epoll/kqueue),
     * which ngx_process_events_and_timers() and ngx_add_channel_event() need.
     */
    for (i = 0; cycle->modules[i]; i++) {
        if (cycle->modules[i]->init_process) {
            if (cycle->modules[i]->init_process(cycle) == NGX_ERROR) {
                ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                              "autocert: init_process failed");
                exit(2);
            }
        }
    }

    /*
     * Drop every peer's channel fds and our own channel[0] end, keeping only
     * channel[1] (== ngx_channel) to receive the master's QUIT/TERMINATE/REOPEN.
     *
     * Unlike a worker, the helper talks to NO peers, so we close BOTH ends of
     * every other slot's channel (a worker keeps peers' channel[0] to message
     * them). This also means later NGX_CMD_OPEN_CHANNEL fds the master passes in
     * are unwanted: the channel handler closes those on arrival.
     */
    for (n = 0; n < ngx_last_process; n++) {

        if (n == ngx_process_slot) {
            continue;
        }

        if (ngx_processes[n].channel[1] != -1
            && close(ngx_processes[n].channel[1]) == -1)
        {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                          "autocert: close() peer channel[1] failed");
        }

        if (ngx_processes[n].channel[0] != -1
            && close(ngx_processes[n].channel[0]) == -1)
        {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                          "autocert: close() peer channel[0] failed");
        }
    }

    if (close(ngx_processes[ngx_process_slot].channel[0]) == -1) {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                      "autocert: close() channel failed");
    }

    if (ngx_add_channel_event(cycle, ngx_channel, NGX_READ_EVENT,
                              ngx_autocert_channel_handler)
        == NGX_ERROR)
    {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                      "autocert: ngx_add_channel_event() failed");
        exit(2);
    }

    ngx_use_accept_mutex = 0;

    ngx_setproctitle(NGX_AUTOCERT_PROC_NAME);

    ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0,
                  "autocert: helper started, pid %P", ngx_pid);

    /* Placeholder activity until the ACME state machine arrives (M4b+). */
    ngx_memzero(&heartbeat, sizeof(ngx_event_t));
    heartbeat.handler = ngx_autocert_heartbeat_handler;
    heartbeat.data = cycle;
    heartbeat.log = cycle->log;
    ngx_add_timer(&heartbeat, NGX_AUTOCERT_HEARTBEAT);

    /*
     * Master-liveness watch. The reload/non-orphan helper is the master's child
     * and is told to quit over the channel. But the cold-start helper is spawned
     * pre-daemon, re-parented to init, and detached in the master's table, so it
     * receives no channel QUIT when the master exits -- it must notice the
     * master is gone and exit itself, else it leaks past shutdown. The watch is
     * cheap and harmless for the channel-managed case (the channel handler fires
     * first there).
     */
    ngx_memzero(&watch, sizeof(ngx_event_t));
    watch.handler = ngx_autocert_watch_handler;
    watch.data = cycle;
    watch.log = cycle->log;
    ngx_add_timer(&watch, NGX_AUTOCERT_WATCH);

    /*
     * Kick off the one-shot ACME directory fetch shortly after startup, off the
     * event loop (so the resolver/connect run with the loop fully up). M4b
     * proof-of-transport; M4c+ replaces this with the real ACME schedule.
     */
    ngx_memzero(&kick, sizeof(ngx_event_t));
    kick.handler = ngx_autocert_kick_handler;
    kick.data = cycle;
    kick.log = cycle->log;
    ngx_add_timer(&kick, NGX_AUTOCERT_KICK);

    for ( ;; ) {

        if (ngx_terminate || ngx_quit) {
            ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0,
                          "autocert: helper exiting, pid %P", ngx_pid);
            exit(0);
        }

        if (ngx_reopen) {
            ngx_reopen = 0;
            ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0,
                          "autocert: reopening logs");
            ngx_reopen_files(cycle, -1);
        }

        ngx_process_events_and_timers(cycle);
    }
}


/*
 * Channel read handler: drains the master->helper channel and sets the global
 * quit/terminate/reopen flags. Based on the relevant arms of nginx's static
 * ngx_channel_handler(). The helper has no peers, so any NGX_CMD_OPEN_CHANNEL
 * fd the master passes (for a new worker/cache helper) is unwanted and closed
 * immediately to avoid leaking it; CLOSE_CHANNEL is a no-op for us.
 *
 * A channel read error/EOF means the master closed its end -- i.e. the master
 * is gone. For the channel-managed helper this is the authoritative shutdown
 * signal (it should normally have received QUIT first), so quit rather than
 * just closing the connection and spinning.
 */
static void
ngx_autocert_channel_handler(ngx_event_t *ev)
{
    ngx_int_t          n;
    ngx_channel_t      ch;
    ngx_connection_t  *c;

    if (ev->timedout) {
        ev->timedout = 0;
        return;
    }

    c = ev->data;

    for ( ;; ) {

        n = ngx_read_channel(c->fd, &ch, sizeof(ngx_channel_t), ev->log);

        if (n == NGX_ERROR) {

            if (ngx_event_flags & NGX_USE_EPOLL_EVENT) {
                ngx_del_conn(c, 0);
            }

            ngx_close_connection(c);

            /* master closed the channel -> master is gone, exit cleanly */
            ngx_quit = 1;
            return;
        }

        if (ngx_event_flags & NGX_USE_EVENTPORT_EVENT) {
            if (ngx_add_event(ev, NGX_READ_EVENT, 0) == NGX_ERROR) {
                return;
            }
        }

        if (n == NGX_AGAIN) {
            return;
        }

        switch (ch.command) {

        case NGX_CMD_QUIT:
            ngx_quit = 1;
            break;

        case NGX_CMD_TERMINATE:
            ngx_terminate = 1;
            break;

        case NGX_CMD_REOPEN:
            ngx_reopen = 1;
            break;

        case NGX_CMD_OPEN_CHANNEL:
            /* a peer's channel fd we don't need: close it, don't record it */
            if (ch.fd != -1 && close(ch.fd) == -1) {
                ngx_log_error(NGX_LOG_ALERT, ev->log, ngx_errno,
                              "autocert: close() passed channel fd failed");
            }
            break;

        default:
            break;
        }
    }
}


/*
 * Heartbeat: a self-rearming timer so the event loop always has at least one
 * timer pending (a loop with no events/timers would block forever in the
 * engine). Replaced by the ACME scheduling timer from M4b.
 */
static void
ngx_autocert_heartbeat_handler(ngx_event_t *ev)
{
    ngx_log_debug1(NGX_LOG_DEBUG_CORE, ev->log, 0,
                   "autocert: helper heartbeat, pid %P", ngx_pid);

    if (!ngx_exiting && !ngx_terminate && !ngx_quit) {
        ngx_add_timer(ev, NGX_AUTOCERT_HEARTBEAT);
    }
}


/*
 * Master-liveness watch handler. For a detached (cold-start) helper that gets
 * no channel QUIT, poll the master's pidfile; once the master is gone, set
 * ngx_quit so the main loop exits cleanly. seen_master guards the startup window
 * where, on a cold start, the pidfile still names the pre-daemon process (which
 * exits) before the daemonized master rewrites it -- don't trust "gone" until a
 * live master has been observed at least once.
 *
 * Bounded startup: if no live master is ever observed within the startup budget
 * (e.g. the master failed to come up after ngx_daemon(), so the pidfile never
 * settles), exit anyway rather than running forever as a stray privileged
 * process.
 */
static void
ngx_autocert_watch_handler(ngx_event_t *ev)
{
    static ngx_uint_t   seen_master;
    static ngx_uint_t   ticks;
    ngx_cycle_t        *cycle = ev->data;

    if (ngx_quit || ngx_terminate || ngx_exiting) {
        return;
    }

    if (ngx_autocert_master_gone(cycle)) {
        if (seen_master) {
            ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0,
                          "autocert: master gone, helper exiting");
            ngx_quit = 1;
            return;
        }

        /* startup window: pidfile not settled yet -- but bound the wait */
        if (++ticks * NGX_AUTOCERT_WATCH >= NGX_AUTOCERT_STARTUP_BUDGET) {
            ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0,
                          "autocert: no master observed within startup budget, "
                          "helper exiting");
            ngx_quit = 1;
            return;
        }

    } else {
        seen_master = 1;
    }

    ngx_add_timer(ev, NGX_AUTOCERT_WATCH);
}


/*
 * One-shot startup kick: build the outbound client (TLS trust + resolver from
 * the HTTP config) on first fire, then GET the CA directory to prove the
 * transport end to end. Failures are logged, not fatal -- the helper keeps
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
                      "autocert: no http{} autocert config; helper idle");
        return;
    }

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

    if (!ngx_autocert_client_ready) {
        if (ngx_autocert_acme_client_create(&ngx_autocert_client, cycle,
                                            &acf.ca_certificate, acf.resolver,
                                            NGX_AUTOCERT_HTTP_TIMEOUT)
            != NGX_OK)
        {
            ngx_log_error(NGX_LOG_ERR, cycle->log, 0,
                          "autocert: failed to build ACME client");
            return;
        }
        ngx_autocert_client.resolver_timeout = acf.resolver_timeout * 1000;
        ngx_autocert_client_ready = 1;
    }

    /* Run the account bootstrap once. */
    if (ngx_autocert_account != NULL) {
        return;                         /* already registering / registered */
    }

    pool = ngx_create_pool(NGX_MIN_POOL_SIZE, cycle->log);
    if (pool == NULL) {
        return;
    }

    ngx_autocert_account = ngx_pcalloc(pool,
                                       sizeof(ngx_autocert_account_t));
    if (ngx_autocert_account == NULL) {
        ngx_destroy_pool(pool);
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
        return;
    }

    /* Keep the account alive; chain into the order flow. */
    ngx_autocert_start_order(cycle);
}


/*
 * Start the M6a order flow for the FIRST collected server name, reusing the
 * live account as the ACME session. One order at a time; multi-name iteration
 * is a later milestone.
 */
static void
ngx_autocert_start_order(ngx_cycle_t *cycle)
{
    ngx_autocert_conf_t    acf;
    ngx_str_t             *names, *first;
    ngx_pool_t            *pool;
    ngx_autocert_order_t  *order;

    if (ngx_autocert_order != NULL) {
        return;                         /* already running */
    }

    if (ngx_autocert_get_conf(cycle, &acf) != NGX_OK || !acf.configured) {
        return;
    }

    if (acf.names == NULL || acf.names->nelts == 0) {
        ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0,
                      "autocert: no server names collected; nothing to order");
        return;
    }
    if (acf.challenge_zone == NULL) {
        ngx_log_error(NGX_LOG_ERR, cycle->log, 0,
                      "autocert: no challenge zone; cannot run order");
        return;
    }

    names = acf.names->elts;
    first = &names[0];

    pool = ngx_create_pool(NGX_MIN_POOL_SIZE, cycle->log);
    if (pool == NULL) {
        return;
    }

    order = ngx_pcalloc(pool, sizeof(ngx_autocert_order_t));
    if (order == NULL) {
        ngx_destroy_pool(pool);
        return;
    }

    /* The domain string aliases the HTTP main-conf pool, which outlives the
     * order; the order copies what it needs into its own pool internally. */
    order->account = ngx_autocert_account;
    order->log = cycle->log;
    order->directory_url = acf.ca;
    order->domain = *first;
    order->challenge_zone = acf.challenge_zone;
    order->key_type = acf.key_type;
    order->store_path = acf.path;
    order->handler = ngx_autocert_order_complete;
    order->data = cycle;

    ngx_autocert_order = order;
    ngx_autocert_order_pool = pool;

    ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0,
                  "autocert: starting ACME order for \"%V\"", first);

    if (ngx_autocert_order_start(order) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, cycle->log, 0,
                      "autocert: could not start ACME order");
        ngx_destroy_pool(pool);
        ngx_autocert_order = NULL;
        ngx_autocert_order_pool = NULL;
    }
}


/*
 * Terminal callback of the order flow. M6b runs the full issuance (finalize →
 * download → store), so NGX_OK here means the certificate is on disk.
 */
static void
ngx_autocert_order_complete(ngx_autocert_order_t *order, ngx_int_t rc)
{
    if (rc == NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, order->log, 0,
                      "autocert: certificate provisioned for \"%V\"",
                      &order->domain);
    } else {
        ngx_log_error(NGX_LOG_ERR, order->log, 0,
                      "autocert: ACME order failed for \"%V\"", &order->domain);
    }

    ngx_autocert_order_free(order);     /* drops token, frees order pool... */
    ngx_autocert_order = NULL;
    if (ngx_autocert_order_pool) {
        ngx_destroy_pool(ngx_autocert_order_pool);
        ngx_autocert_order_pool = NULL;
    }
}


/*
 * True iff the master process has gone: its pidfile is absent (clean exit) or
 * names a pid that is no longer alive. Reads the path from the core module's pid
 * setting so it honours the `pid` directive and -p prefix.
 *
 * Robustness (M1.5):
 *   - Only ENOENT/ENOTDIR (the pidfile is really gone) counts as "master gone".
 *     A transient open error (EMFILE, EACCES, EINTR) must NOT be read as a dead
 *     master, or we would kill the helper on a hiccup.
 *   - Strict decimal parse of the pid: stop at the first non-digit, reject empty.
 *   - kill(pid, 0): ESRCH => gone; EPERM => alive (different owner); other errors
 *     are inconclusive and treated as alive.
 */
static ngx_uint_t
ngx_autocert_master_gone(ngx_cycle_t *cycle)
{
    ngx_fd_t          fd;
    ssize_t           n;
    ngx_int_t         mpid;
    size_t            len;
    ngx_err_t         err;
    u_char           *p, buf[NGX_INT64_LEN + 2];
    ngx_core_conf_t  *ccf;

    ccf = (ngx_core_conf_t *) ngx_get_conf(cycle->conf_ctx, ngx_core_module);

    fd = ngx_open_file(ccf->pid.data, NGX_FILE_RDONLY, NGX_FILE_OPEN, 0);
    if (fd == NGX_INVALID_FILE) {
        err = ngx_errno;
        if (err == NGX_ENOENT || err == NGX_ENOTDIR) {
            return 1;                      /* pidfile removed -> master gone */
        }
        return 0;                          /* transient error -> assume alive */
    }

    n = ngx_read_fd(fd, buf, sizeof(buf) - 1);
    ngx_close_file(fd);

    if (n <= 0) {
        return 0;                          /* unreadable -> inconclusive */
    }

    /* strict decimal: digits up to the first non-digit (e.g. the trailing \n) */
    len = 0;
    for (p = buf; p < buf + n; p++) {
        if (*p < '0' || *p > '9') {
            break;
        }
        len++;
    }

    if (len == 0) {
        return 0;
    }

    mpid = ngx_atoi(buf, len);
    if (mpid == NGX_ERROR || mpid <= 0) {
        return 0;
    }

    if (kill((ngx_pid_t) mpid, 0) == -1 && ngx_errno == NGX_ESRCH) {
        return 1;                          /* pid no longer exists */
    }

    return 0;
}


/*
 * Close every inherited listening socket, including the QUIC/UDP and reuseport
 * listeners that ngx_close_listening_sockets() leaves open. The helper serves
 * no traffic, so none of these should remain open in it.
 */
static void
ngx_autocert_close_listening(ngx_cycle_t *cycle)
{
    /*
     * Close ONLY the QUIC/UDP listeners first: ngx_close_listening_sockets()
     * skips those (NGX_QUIC) and then zeroes cycle->listening.nelts, so a loop
     * after it would see nothing. Touch nothing else here -- pre-closing a
     * normal TCP listener and setting fd=-1 would make the nginx call below
     * close(-1) and log EBADF/EMERG for it. (Compiled out entirely when the
     * build has no QUIC, since then there are no skipped listeners.)
     */
#if (NGX_QUIC)
    ngx_uint_t        i;
    ngx_listening_t  *ls;

    ls = cycle->listening.elts;
    for (i = 0; i < cycle->listening.nelts; i++) {
        if (ls[i].quic && ls[i].fd != (ngx_socket_t) -1) {
            if (ngx_close_socket(ls[i].fd) == -1) {
                ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_socket_errno,
                              ngx_close_socket_n " on QUIC listen socket failed");
            }
            ls[i].fd = (ngx_socket_t) -1;
        }
    }
#endif

    /* shared/TCP listeners + their connection teardown */
    ngx_close_listening_sockets(cycle);
}
