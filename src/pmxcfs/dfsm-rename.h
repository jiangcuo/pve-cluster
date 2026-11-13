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

/* Rename the public functions of dfsm.h for one backend implementation, so
 * that the CPG (dfsm.c) and the raft (dfsm-raft.c) backend can both be linked
 * into pmxcfs. dfsm-backend.c implements the dfsm.h API and dispatches to the
 * backend selected at startup.
 *
 * Force-included (gcc -include) when compiling a backend, with
 * DFSM_RENAME_CPG or DFSM_RENAME_RAFT defined. Keeps dfsm.c unmodified.
 */

#ifndef _PVE_DFSM_RENAME_H_
#define _PVE_DFSM_RENAME_H_

#if defined(DFSM_RENAME_CPG)
#define DFSM_IMPL(name) dfsm_cpg_##name
#elif defined(DFSM_RENAME_RAFT)
#define DFSM_IMPL(name) dfsm_raft_##name
#else
#error "define DFSM_RENAME_CPG or DFSM_RENAME_RAFT"
#endif

#define dfsm_new DFSM_IMPL(new)
#define dfsm_destroy DFSM_IMPL(destroy)
#define dfsm_initialize DFSM_IMPL(initialize)
#define dfsm_finalize DFSM_IMPL(finalize)
#define dfsm_join DFSM_IMPL(join)
#define dfsm_leave DFSM_IMPL(leave)
#define dfsm_dispatch DFSM_IMPL(dispatch)
#define dfsm_restartable DFSM_IMPL(restartable)
#define dfsm_is_initialized DFSM_IMPL(is_initialized)
#define dfsm_set_errormode DFSM_IMPL(set_errormode)
#define dfsm_send_message DFSM_IMPL(send_message)
#define dfsm_send_message_sync DFSM_IMPL(send_message_sync)
#define dfsm_send_update DFSM_IMPL(send_update)
#define dfsm_send_update_complete DFSM_IMPL(send_update_complete)
#define dfsm_lowest_nodeid DFSM_IMPL(lowest_nodeid)
#define dfsm_nodeid_is_local DFSM_IMPL(nodeid_is_local)
#define dfsm_verify_request DFSM_IMPL(verify_request)
#define service_dfsm_new DFSM_IMPL(service_new)
#define service_dfsm_destroy DFSM_IMPL(service_destroy)

#endif /* _PVE_DFSM_RENAME_H_ */
