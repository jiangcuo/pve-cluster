#ifndef _PVE_DFSM_RAFT_H_
#define _PVE_DFSM_RAFT_H_

#include <glib.h>

#include "cfs-utils.h"
#include "dfsm.h"

/* local files, not replicated; raft.conf existing selects the raft backend */
#define RAFT_CONF VARLIBDIR "/raft.conf"
#define RAFT_AUTHKEY VARLIBDIR "/authkey"

typedef enum { DFSM_BACKEND_CPG = 0, DFSM_BACKEND_RAFT = 1 } dfsm_backend_t;

/* select the dfsm implementation, once at startup before any dfsm_new() */
void dfsm_set_backend(dfsm_backend_t backend);

gboolean dfsm_backend_is_raft(void);

/* parse RAFT_CONF and publish the node list to the status module */
gboolean dfsm_raft_load_config(const char *filename, const char *nodename);

/* raft state and members as JSON; returns 0 or a negative errno */
int dfsm_raft_get_status(GString *out);

/* result of a membership change: 0 or a negative errno (the reason is logged) */
typedef void (*dfsm_raft_change_cb)(gpointer data, int result);

/* start a membership change "add <id> <name> <ip>" or "remove <id>", run by the
 * leader. Returns 0 if started, cb is then called once on the raft thread with
 * the result; or a negative errno if it could not be started (cb is not called). */
int dfsm_raft_change(const char *cmd, dfsm_raft_change_cb cb, gpointer data);

/* serialize the complete application state, result is freed with g_free */
typedef gpointer (*dfsm_raft_snapshot_fn_t)(gpointer data, size_t *res_len);

/* replace the complete application state */
typedef gboolean (*dfsm_raft_restore_fn_t)(gpointer data, const void *buf, size_t len);

void dfsm_raft_set_snapshot_callbacks(
    dfsm_t *dfsm, dfsm_raft_snapshot_fn_t snapshot_fn, dfsm_raft_restore_fn_t restore_fn
);

#endif /* _PVE_DFSM_RAFT_H_ */
