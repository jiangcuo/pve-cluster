/*
  Copyright (C) 2026 Lierfang

  This program is free software: you can redistribute it and/or modify
  it under the terms of the GNU Affero General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU Affero General Public License for more details.

  You should have received a copy of the GNU Affero General Public License
  along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

/* dfsm.h API, dispatched to the backend selected once at startup: corosync
 * CPG (dfsm.c) or raft (dfsm-raft.c). See dfsm-rename.h. */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /* HAVE_CONFIG_H */

#include <glib.h>

#include "dfsm-raft.h"
#include "dfsm.h"

#define DFSM_DECLARE(P)                                                                            \
    dfsm_t *P##new(                                                                                \
        gpointer data,                                                                             \
        const char *group_name,                                                                    \
        const char *log_domain,                                                                    \
        guint32 protocol_version,                                                                  \
        dfsm_callbacks_t *callbacks                                                                \
    );                                                                                             \
    void P##destroy(dfsm_t *dfsm);                                                                 \
    cs_error_t P##initialize(dfsm_t *dfsm, int *fd);                                               \
    gboolean P##finalize(dfsm_t *dfsm);                                                            \
    cs_error_t P##join(dfsm_t *dfsm);                                                              \
    cs_error_t P##leave(dfsm_t *dfsm);                                                             \
    cs_error_t P##dispatch(dfsm_t *dfsm, cs_dispatch_flags_t dispatch_types);                      \
    gboolean P##restartable(dfsm_t *dfsm);                                                         \
    gboolean P##is_initialized(dfsm_t *dfsm);                                                      \
    void P##set_errormode(dfsm_t *dfsm);                                                           \
    cs_error_t P##send_message(dfsm_t *dfsm, uint16_t msgtype, struct iovec *iov, int len);        \
    cs_error_t P##send_message_sync(                                                               \
        dfsm_t *dfsm, uint16_t msgtype, struct iovec *iov, int len, dfsm_result_t *rp              \
    );                                                                                             \
    cs_error_t P##send_update(dfsm_t *dfsm, struct iovec *iov, unsigned int len);                  \
    cs_error_t P##send_update_complete(dfsm_t *dfsm);                                              \
    gboolean P##lowest_nodeid(dfsm_t *dfsm);                                                       \
    gboolean P##nodeid_is_local(dfsm_t *dfsm, uint32_t nodeid, uint32_t pid);                      \
    cs_error_t P##verify_request(dfsm_t *dfsm);                                                    \
    cfs_service_t *P##service_new(dfsm_t *dfsm);                                                   \
    void P##service_destroy(cfs_service_t *service);

DFSM_DECLARE(dfsm_cpg_)
DFSM_DECLARE(dfsm_raft_)

static dfsm_backend_t backend = DFSM_BACKEND_CPG;

void dfsm_set_backend(dfsm_backend_t b) { backend = b; }

gboolean dfsm_backend_is_raft(void) { return backend == DFSM_BACKEND_RAFT; }

#define DISPATCH(fn, ...)                                                                          \
    (backend == DFSM_BACKEND_RAFT ? dfsm_raft_##fn(__VA_ARGS__) : dfsm_cpg_##fn(__VA_ARGS__))

dfsm_t *dfsm_new(
    gpointer data,
    const char *group_name,
    const char *log_domain,
    guint32 protocol_version,
    dfsm_callbacks_t *callbacks
) {
    return DISPATCH(new, data, group_name, log_domain, protocol_version, callbacks);
}

void dfsm_destroy(dfsm_t *dfsm) { DISPATCH(destroy, dfsm); }

cs_error_t dfsm_initialize(dfsm_t *dfsm, int *fd) { return DISPATCH(initialize, dfsm, fd); }

gboolean dfsm_finalize(dfsm_t *dfsm) { return DISPATCH(finalize, dfsm); }

cs_error_t dfsm_join(dfsm_t *dfsm) { return DISPATCH(join, dfsm); }

cs_error_t dfsm_leave(dfsm_t *dfsm) { return DISPATCH(leave, dfsm); }

cs_error_t dfsm_dispatch(dfsm_t *dfsm, cs_dispatch_flags_t dispatch_types) {
    return DISPATCH(dispatch, dfsm, dispatch_types);
}

gboolean dfsm_restartable(dfsm_t *dfsm) { return DISPATCH(restartable, dfsm); }

gboolean dfsm_is_initialized(dfsm_t *dfsm) { return DISPATCH(is_initialized, dfsm); }

void dfsm_set_errormode(dfsm_t *dfsm) { DISPATCH(set_errormode, dfsm); }

cs_error_t dfsm_send_message(dfsm_t *dfsm, uint16_t msgtype, struct iovec *iov, int len) {
    return DISPATCH(send_message, dfsm, msgtype, iov, len);
}

cs_error_t dfsm_send_message_sync(
    dfsm_t *dfsm, uint16_t msgtype, struct iovec *iov, int len, dfsm_result_t *rp
) {
    return DISPATCH(send_message_sync, dfsm, msgtype, iov, len, rp);
}

cs_error_t dfsm_send_update(dfsm_t *dfsm, struct iovec *iov, unsigned int len) {
    return DISPATCH(send_update, dfsm, iov, len);
}

cs_error_t dfsm_send_update_complete(dfsm_t *dfsm) { return DISPATCH(send_update_complete, dfsm); }

gboolean dfsm_lowest_nodeid(dfsm_t *dfsm) { return DISPATCH(lowest_nodeid, dfsm); }

gboolean dfsm_nodeid_is_local(dfsm_t *dfsm, uint32_t nodeid, uint32_t pid) {
    return DISPATCH(nodeid_is_local, dfsm, nodeid, pid);
}

cs_error_t dfsm_verify_request(dfsm_t *dfsm) { return DISPATCH(verify_request, dfsm); }

cfs_service_t *service_dfsm_new(dfsm_t *dfsm) { return DISPATCH(service_new, dfsm); }

void service_dfsm_destroy(cfs_service_t *service) { DISPATCH(service_destroy, service); }
