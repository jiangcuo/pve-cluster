# pmxcfs Raft Backend

This document describes the design and the code of the Raft backend of pmxcfs, for developers
working on it.

## Overview

pmxcfs replicates `/etc/pve` with corosync CPG. Every message goes around the totem ring, and
every membership change makes all nodes exchange their memdb state and resynchronize. Both get
slower as the cluster grows.

The Raft backend replaces CPG as the transport behind the `dfsm.h` interface. dcdb, memdb, FUSE,
IPC and the Perl side keep working as before.

- `/etc/pve` messages become entries of a Raft log, committed by a majority of a small set of
  voters (3 by default).
- Every other node is a non-voting standby with a full copy.
- Status data (kvstore: node status, RRD, cluster log) is not ordered, so it does not go through
  the log. Every follower keeps one connection to the leader, the *side channel*, and the leader
  relays kvstore traffic between the nodes.

The backend is chosen at startup: if `/var/lib/pve-cluster/raft.conf` exists, pmxcfs uses Raft,
otherwise corosync. The Raft implementation is libraft (legacy API) with its libuv I/O backend.

## Code map

| File | Content |
|---|---|
| `dfsm-raft.c` | The whole Raft backend: configuration, Raft FSM, snapshots, node table, side channel, kvstore hub, membership changes, IPC entry points, and the `dfsm.h` implementation. |
| `dfsm-raft.h` | Backend selection, configuration loading, snapshot callback registration, IPC entry points. |
| `rsm-tls.c`, `rsm-tls.h` | TLS connections (listener, connect, accept) and the `raft_uv_transport` given to libraft. |
| `dfsm-backend.c` | `dfsm.h` dispatch to the CPG (`dfsm.c`) or the Raft implementation. |
| `dcdb.c` | `dcdb_snapshot_create()` and `dcdb_snapshot_restore()`; the apply path skips the local quorum check in Raft mode. |
| `pmxcfs.c` | Startup in Raft mode. |
| `server.c`, `cfs-ipc-ops.h` | IPC requests `CFS_IPC_GET_RAFT_STATUS` and `CFS_IPC_RAFT_CHANGE`. |

Inside `dfsm-raft.c` the state lives in one static `rsm_t R`. There is one engine per process,
shared by the two dfsm instances that pmxcfs creates:

| dfsm instance | Group | Kind | Uses |
|---|---|---|---|
| dcdb | `pve_dcdb_v1` | `DFSM_KIND_DCDB` | Raft log |
| status | `pve_kvstore_v1` | `DFSM_KIND_HUB` | side channel |

## Threads and locking

All Raft and network work runs on one thread: the `raft` thread, which runs `R.loop` (libuv).
The other threads never touch libraft or a libuv handle. They queue work under `R.mutex` and wake
the Raft thread with `uv_async_send(&R.async)`.

| Thread | Calls into the backend | Waits |
|---|---|---|
| FUSE threads | `dfsm_send_message_sync()` (dcdb writes) | on `R.cond` until the entry is applied locally (see "Write path") |
| main loop worker | `dfsm_initialize()`, `dfsm_dispatch()`, kvstore sends | no |
| IPC server thread | `dfsm_raft_get_status()` | on `R.cond` for the reply, which the Raft thread answers locally |
| IPC server thread | `dfsm_raft_change()` | no: the change completes later, see "Membership changes" |
| raft thread | everything else | never blocks |

`R.mutex` protects the following; everything else in `R` belongs to the Raft thread.

| Field | Content |
|---|---|
| `R.results` | waiting writers, keyed by request id |
| `R.reqcount` | request id counter |
| `R.outq` | dcdb entries to submit |
| `R.hubq` | kvstore messages to send |
| `R.ctlq` | IPC requests |

`R.inflight` (sent local writes, see "Write path") belongs to the Raft thread.

The dfsm callbacks (`dcdb_deliver`, the kvstore confchg, deliver and state callbacks) run on the
Raft thread. With CPG they run on the main loop worker. They already lock what they touch (memdb
mutex, status mutex), so they work unchanged.

`rsm_flush()` moves the queues out under the lock and sends after releasing it, because sending
may end up in status callbacks. `side_write()` never closes a connection; a broken connection is
reported by its read callback.

The dfsm service fd (an eventfd per instance) is never signalled. It only exists because the
pmxcfs service loop expects a file descriptor; nothing is delivered through it.

## Startup

`main()` in `pmxcfs.c`:

1. `raft.conf` exists → `dfsm_set_backend(DFSM_BACKEND_RAFT)`, `dfsm_raft_load_config()`.
2. Delete `config.db`. memdb starts empty and is rebuilt from the latest snapshot and the log.
3. Skip the import of `corosync.conf`, the quorum service and the confdb service.
4. Create dcdb and the status dfsm. `dcdb_new()` registers the snapshot callbacks.

The engine starts with the first `dfsm_initialize()` after the dcdb instance exists, in `rsm_start()`:

1. Read the key and set up TLS.
2. `raft_uv_init()` on `/var/lib/pve-cluster/raft/` with our transport.
3. `raft_init()` and set the timeouts.
4. `raft_bootstrap()` if `raft.conf` has `member` lines. Only the node that created the cluster has
   them; `RAFT_CANTBOOTSTRAP` on later starts is ignored.
5. Publish the node list.
6. Listen.
7. `raft_start()`.
8. Start the 100 ms timer and the Raft thread.

The status instance initializes after that and requests a hub resync (see "Side channel").

`raft.conf` format:

```
cluster <name>
local <id> <name> <address>
voters <n>                       # optional, default 3
member <id> <name> <address> voter   # only on the node that creates the cluster
```

## Replicated state

The FSM applies two kinds of log entries. Both start with `rsm_hdr_t`:

| Field | Size | |
|---|---|---|
| magic | u32 | entry type |
| msgtype | u16 | dcdb message type |
| reserved | u16 | |
| nodeid | u32 | origin node |
| pid | u32 | origin process |
| time | u32 | origin time; `dcdb_deliver` uses it as the message time |
| len | u32 | payload length; the entry is padded to 8 bytes |
| reqid | u64 | origin request id; 0 if nobody waits. Starts at a random value per process, so that (pid, reqid) does not repeat after a restart |

The two entry types:

| Magic | Payload | Apply |
|---|---|---|
| `RSM_MAGIC_DCDB` | dcdb message, the same bytes CPG would send | `dcdb_deliver()`, then the result is recorded in the origin's result ring |
| `RSM_MAGIC_NODE` | `rsm_node_msg_t`: `NODE_SET` or `NODE_DEL` with `rsm_node_t` (id, role, name, address) | updates the node table, republishes `.members` |

**Result rings** (`R.rings`, one `rsm_ring_t` per origin node, the last 256 results) are part of
the replicated state. They serve two purposes:

- When a node installs a snapshot, entries covered by it are never applied locally.
  `rsm_complete_from_rings()` then completes the local writers from the rings instead.
- Apply drops an entry whose (pid, reqid) is already in its origin's ring: a write can be sent
  more than once, and it must take effect once.

**Node table** (`R.nodes`). The Raft configuration only knows id, address and role. Names are
needed for `.members`, so they are replicated in the node table. Its role field is used for the
vote count in `.members` (voter 1, others 0). The authoritative role is the one in the Raft
configuration.

**Snapshot.** Taken every 1024 entries; 1024 trailing entries are kept, so slightly lagging
followers get the log instead of a snapshot. Layout:

| Part | Content |
|---|---|
| header | u32 magic `RSM_SNAPSHOT_MAGIC`, u32 number of rings, u32 number of nodes |
| rings | `rsm_ring_t` × number of rings |
| nodes | `rsm_node_t` × number of nodes |
| dcdb snapshot | u32 magic `DCDB_SNAPSHOT_MAGIC`, u32 index size, the memdb index (`memdb_encode_index`), then every tree entry as u32 length + the inode record of the CPG state transfer (`dcdb_parse_update_inode` format) |

`dcdb_snapshot_restore()` parses the snapshot completely before it changes anything, then calls
`bdb_backend_commit_update()`. That writes all entries, deletes entries that are not in the
snapshot, reloads memdb and checks the result against the snapshot index, in one database
transaction. If the restore fails, the backend goes into error mode.

All binary formats use host byte order, like `dfsm.c`.

## Write path

```
FUSE thread                          raft thread (follower)          raft thread (leader)
dcdb_send_fuse_message()
 dfsm_send_message_sync()
  build entry, reqid, R.results
  push R.outq, uv_async_send ------> rsm_async_cb()
  wait on R.cond                      rsm_flush()
                                       side_write(SF_ENTRY) -------> side_dispatch(SF_ENTRY)
                                                                      rsm_submit() = raft_apply()
                                     ... commit ...                   ... commit ...
                                     rsm_fsm_apply()                  rsm_fsm_apply()
                                      dcdb_deliver()                   dcdb_deliver()
                                      record in ring
                                      own entry: rsm_complete() -+
  <---------------------------------------------------------------+
  return the apply result
```

On the leader, `rsm_flush()` calls `rsm_submit()` directly.

The writer waits for its own entry to be applied **on its own node**. A write followed by a read
on the same node therefore sees the write (read-your-writes), the same as with CPG.

A writer only fails when the outcome is certain. Once an entry has left the node, the node cannot
know whether it will commit until it sees it applied: the leader may have appended it and then
lost the connection. So the writer waits for the apply, and the entry is sent again until then.

| Situation | Behaviour |
|---|---|
| Not sent within 10 s (no leader, no connection) | the writer takes the entry back from `R.outq` and fails with `-ETIMEDOUT`; it can never be applied |
| Sent | `rsm_flush()` moves the entry to `R.inflight`; the writer waits until it is applied |
| Leader changed, connection to the leader re-established | `rsm_resend(TRUE)` sends every entry in `R.inflight` again |
| Not applied 3 s after it was last sent | `rsm_resend(FALSE)` from the timer sends it again |
| Applied (from the log or a snapshot) | `rsm_complete()` wakes the writer and removes the entry from `R.inflight` |
| Applied again (a resent copy) | dropped by `rsm_fsm_apply()`: (pid, reqid) is already in the result ring |

A write that is in flight when a partition starts blocks until the partition heals. New writes on
the isolated node fail right away (`-EACCES`, not quorate). For HA this is the safe direction: an
isolated node cannot renew its locks and is fenced by its watchdog.

A node is quorate when it knows a leader (`raft_leader()` returns an id). The timer checks this
every 100 ms and calls `cfs_set_quorate()`. dcdb refuses writes while not quorate, as before.
Safety does not depend on this flag: without a majority of voters nothing commits.

**Apply must be deterministic.** In Raft mode `dcdb_deliver` does not check the local quorum
state: a committed entry is always applied. The quorum check before a write is submitted stays.

**Locks.** `dfsm_lowest_nodeid()` returns true on the leader, so the leader processes
`UNLOCK_REQUEST` and sends `UNLOCK`. This function is only called from apply, on the Raft thread.

- Lock timers live in the leader's memory. A new leader starts them from zero, so a lock expires
  later, never earlier.
- `UNLOCK` keeps its checksum, so a lock renewed meanwhile is not removed.

**Error mode.** These put the backend into error mode:

- a negative `dcdb_deliver` result;
- a malformed snapshot;
- a failed snapshot restore;
- `dfsm_set_errormode()`.

In error mode further sends fail with `CS_ERR_NOT_EXIST` and the service is not restartable.
pmxcfs must be restarted, and then rebuilds memdb from the snapshot and the log.

## Membership changes

Requests come in over IPC on any node: `dfsm_raft_change("add <id> <name> <address>", cb, data)`
or `dfsm_raft_change("remove <id>", cb, data)`. A change can take long: it runs on the leader and
waits for the Raft configuration change to commit. The IPC server thread therefore does not wait:

1. `s1_msg_process_fn()` takes a reference on the client connection, starts the change and
   returns without a reply.
2. The request is queued on `R.ctlq`, and the Raft thread runs `ctl_exec()`.
3. When the change completes, `raft_change_done()` runs on the Raft thread. It queues the
   result and signals an eventfd that the IPC server loop watches.
4. `deferred_reply_dispatch()` on the IPC server thread sends the reply and drops the
   connection reference.

The client blocks as before; other IPC clients are served meanwhile.

On a follower, `ctl_exec()` forwards the command to the leader as `SF_CTL` and keeps it in
`R.ctl_pending`. The reply (`SF_CTL_REPLY`: id, result, text) completes it; it expires after 60 s.
On the leader, the command runs locally:

```
add:  raft_add(id, address)            spare; plus NODE_SET (name, address)
       -> ctl_add_cb: raft_assign(id, STANDBY)
          -> ctl_assign_cb: NODE_SET with the final role, reply ok
       on failure after raft_add: ctl_add_failed -> raft_remove -> NODE_DEL, reply error

remove: raft_remove(id) -> ctl_remove_cb: NODE_DEL, reply
```

`maintain_voters()` runs on the leader every 5 s. It keeps `R.voters` voters: while voters are
missing, it promotes a standby that is online (connected to the leader) with
`raft_assign(VOTER)`. Removed voters are replaced the same way.

Only one change runs at a time (`R.change_pending`); libraft rejects concurrent changes with
`RAFT_CANTCHANGE`, which is returned as `-EBUSY`. Every reply carries a negative errno
(`raft_errno()` maps libraft errors) and a text. The text is logged on the node that asked.

The status request is answered locally, without the leader. `ctl_status()` returns JSON:

- cluster, nodeid, state, term, leader, quorate, voters, last_index, applied_index;
- members, each with id, name, ip, role and online.

## Side channel

Every follower keeps one connection to the current leader (`R.up`). The leader keeps the incoming
ones in `R.down`, keyed by node id. Each tick, `up_check()` (re)connects to the address that
`raft_leader()` reports.

Frames are `u32 length` (type byte plus payload), `u8 type`, payload:

| Type | Direction | Payload |
|---|---|---|
| `SF_HELLO` | follower → leader | nodeid, pid |
| `SF_ENTRY` | follower → leader | a log entry to submit |
| `SF_HUB` | both | `hub_hdr_t` (nodeid, pid, time, msgtype) + kvstore message |
| `SF_VIEW` | leader → follower | epoch, count, (nodeid, pid) × count |
| `SF_STATE` | both | epoch, nodeid, pid, kvstore state |
| `SF_CTL` | follower → leader | request id, command |
| `SF_CTL_REPLY` | leader → follower | request id, result, text |
| `SF_PING` | both | none |

**Access.** An incoming connection must send `SF_HELLO` first, and only to the leader. The node id
must be in the current Raft configuration. A removed node still has the key, but is rejected
here and cannot submit entries.

**kvstore hub.** A kvstore send (`hub_send()`) is queued on `R.hubq`.

- A follower sends it to the leader.
- The leader delivers it locally and relays it to every other follower.
- A node never gets its own messages back; the kvstore deliver callback ignores them anyway.

**View.** The leader plus the nodes connected to it form the membership view, which drives the
online flags. On every change (HELLO, connection closed, new leader), `hub_view_changed()` runs on
the leader:

1. Increment the epoch.
2. Send `SF_VIEW` to all followers.
3. Run confchg and synced locally (as after a CPG configuration change; synced re-announces the
   node IP).
4. Send its own state.

A follower that receives `SF_VIEW` does steps 3 and 4 itself. The leader relays every
`SF_STATE`. A node receiving a state with the current epoch merges it with its own state
(`hub_process_state()`, one remote node at a time), which merges the cluster log. Stale epochs are
ignored. Without a leader, the view is the node alone and the kvstore queue is bounded to 10000
messages.

The status dfsm can initialize after the side channel is already up. Messages and views that
arrived before were dropped, so `dfsm_initialize()` sets `R.hub_resync_pending`, and the Raft
thread runs `hub_resync()`:

- on the leader: a new view;
- on a follower: reconnect, so the leader announces a new view;
- without a leader: a view of the node alone.

**Liveness.** Pings go both ways every second; a connection silent for 3 s is closed. A peer that
disappears without a TCP reset therefore goes offline within 3 s.

**Leader change.**

- A new leader closes its own `R.up`, publishes the bootstrap members if they are missing from the
  node table, and announces a view.
- A node that loses leadership closes all of `R.down` and falls back to a view of itself.

## Transport

`rsm-tls.c` provides TLS connections that look like plain `uv_stream_t` to their users. A
connection (`tls_conn_t`) consists of:

- the TCP handle;
- an OpenSSL `SSL` with two memory BIOs;
- a socketpair.

TLS runs on the TCP side. The plaintext goes through the socketpair: one end is read and written
by `tls_conn_t`, the other end is handed to the user as a `uv_pipe_t` allocated with
`raft_malloc()`, as libraft expects. A connection is reference counted over its handles (TCP,
handshake timer, inner pipe). Closing either side closes all of them.

**Handshake.** TLS 1.3 only, cipher `TLS_AES_128_GCM_SHA256`, external PSK with identity
`pmxcfs`. The PSK is SHA-256 of the key file `/var/lib/pve-cluster/authkey`. There are no
certificates and no session tickets. The handshake must finish within 5 s.

**Preamble.** Right after the handshake the client sends a fixed size preamble:

- magic `PRA1`;
- kind: `RSM_KIND_RAFT` or `RSM_KIND_SIDE`;
- sender Raft id;
- sender address.

The server reads it before it hands out the stream, so one listener on port 5420 serves both
Raft traffic and the side channel. `rsm_accept_cb()` in `dfsm-raft.c` dispatches on the kind:

- Raft connections go to `rsm_tls_transport_accept()`, which calls libraft's accept callback;
- side channel connections go to `side_new()`.

**libraft transport.** `rsm_tls_transport_init()` implements `raft_uv_transport` version 1:

- `init` stores the local id and address;
- `listen` only stores the accept callback, because the shared listener accepts;
- `connect` splits `host:port` and calls `rsm_tls_connect()` with a Raft preamble;
- `close` marks the transport closed.

The listener binds to the node's cluster address only. Addresses are IPv4 for now.

## Perl integration

The Perl side does not know about the internals. It uses:

- `PVE::Cluster::get_cluster_backend()`: `raft` if `raft.conf` exists, `corosync` if
  `corosync.conf` exists, else undef;
- `get_raft_status()` and `get_raft_nodelist()`: the status IPC; the nodelist has the same shape
  as `PVE::Corosync::nodelist`;
- `raft_add_node()` and `raft_remove_node()`: the change IPC; they die with the errno text.

`PVE::Cluster::Setup`:

- writes `raft.conf` and the key;
- creates a cluster (`raft_create_cluster()`), saving `/etc/pve` and restoring it into the new
  cluster;
- joins a node (`finish_join_raft()`);
- rolls back a failed create (`raft_create_rollback()`).

`PVE::API2::ClusterConfig` and `pvecm` branch on the backend in `create`, `addnode`, `delnode`,
join info, nodes, totem, status and nodes output. For Raft clusters the API returns
corosync-shaped data with only link 0, so existing API users keep working.

## Design decisions

**Only `/etc/pve` goes through Raft.** kvstore data is written by one node per key, last writer
wins, and RRD updates are frequent. Putting it into the log would add ordering nobody needs and
grow the log and the snapshots.

**The leader is the kvstore hub.** It needs one connection per follower, which every follower
already has for forwarding writes. It also yields a single, consistent online view, decided by
one node. The cost is that the leader carries all kvstore traffic (see TODO). Alternatives:

- a full mesh: O(N²) connections, the problem we want to leave behind;
- gossip: a weaker and more complex view.

**Forwarding over our own channel.** libraft's legacy API has no request forwarding, and only the
leader can append.

**Writers wait for the local apply.** pmxcfs users read right after writing, and CPG gives
read-your-writes. Waiting for the commit only would make reads on a follower stale.

**Replicated result rings.** Results kept only in local memory would be lost when a follower
catches up through a snapshot, and its writer would get no result.

**Resend and deduplicate instead of timing out sent writes.** A node cut off from the leader cannot
tell whether a sent entry will still commit. A timeout would report a failure for a write that may
still take effect, which breaks callers such as the lock code. Waiting for the apply, resending
and dropping duplicates on apply gives every writer the real result, at the cost of blocking the
writes that are in flight during a partition.

**Join as standby, promote later.** A new node only catches up after its join has finished. As a
voter it would count towards the majority before it can vote, which lowers availability, and
with two nodes it could stop the cluster.

**Node table next to the Raft configuration.** libraft only stores id, address and role, and
pmxcfs needs node names.

**The leader expires locks.** The leader is the only node that is guaranteed to be up to date.
A new leader restarting the timers only delays lock expiry.

**Rebuild memdb at startup.** It avoids keeping the applied index in sync with the SQLite
database. It costs startup time with a large `/etc/pve` (see TODO).

**One port, preamble, TLS through a socketpair.** libraft only accepts a plain `uv_stream_t`
from its transport; this keeps libraft unchanged. The cost is one extra copy through the
socketpair.

**PSK instead of certificates.** The key must be readable before `/etc/pve` exists, and
`pve-ssl` can be replaced by ACME or the user. This is the same model as the corosync authkey.

**One address per node.** Link redundancy is left to bonding. Multiple Raft addresses per node
would need our own failover in the transport.

## TODO

- HA fault injection:
  - isolated leader;
  - isolated node running HA services;
  - symmetric and asymmetric partitions;
  - frequent leader changes;
  - a stopped pmxcfs;
  - wall clock jumps.
- Lock expiry on a monotonic clock (`memdb_lock_expired()` uses wall clock time).
- Do not serve `/etc/pve` while memdb is rebuilt at startup, or persist the applied index with
  memdb to avoid the rebuild.
- Protocol version in the preamble and in `SF_HELLO`, for rolling upgrades.
- Key rotation; per node identities (cluster CA and node certificates) to verify node ids.
- IPv6.
- Replace voters that stay offline; demote surplus voters; change `voters` at runtime.
- Change a node's address or name.
- The leader relays all kvstore traffic: measure with many nodes, relay in tiers if needed.
- Benchmarks against corosync with 16, 32 and 48+ nodes: write latency, lock latency, recovery
  time, slow nodes, traffic.
