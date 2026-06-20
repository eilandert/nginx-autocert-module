/*
 * ngx_autocert_driver — public entry points for the worker-0 ACME engine
 * driver. The driver runs the process-agnostic ACME state machine (account
 * bootstrap, order flow, renewal scheduler) on worker 0's event loop. The
 * caller (the http module's init_process / exit_process) is responsible for
 * gating these to worker 0 (or single-process mode).
 */

#ifndef NGX_AUTOCERT_DRIVER_H_INCLUDED
#define NGX_AUTOCERT_DRIVER_H_INCLUDED


#include <ngx_config.h>
#include <ngx_core.h>


/* Arm the ACME engine on the current (worker-0) process. */
void ngx_autocert_driver_init_process(ngx_cycle_t *cycle);

/* Tear the ACME engine state down on worker exit (best-effort frees). */
void ngx_autocert_driver_exit_process(ngx_cycle_t *cycle);


#endif /* NGX_AUTOCERT_DRIVER_H_INCLUDED */
