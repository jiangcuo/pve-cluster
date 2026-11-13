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

/* dfsm.h implemented on top of libraft instead of corosync CPG, selected at
 * startup when RAFT_CONF exists. Design and open points: raft.md in the
 * source tree.
 *
 * One engine serves both dfsm instances of pmxcfs:
 *
 * - dcdb (/etc/pve): every message is a raft log entry. Non-leaders forward
 *   entries to the leader over the side channel. A writer waits until its own
 *   entry was applied locally (read-your-writes, like CPG). Apply results are
 *   kept in replicated per-node rings, so a writer whose entry arrived inside
 *   a snapshot still gets its result. Snapshots carry the memdb, the rings and
 *   the node table. The leader takes the role of the lowest node id (lock
 *   expiry); quorate means a leader is known.
 *
 * - kvstore (status, RRD, cluster log): not replicated through raft. The
 *   leader acts as a hub on the side channel: it relays messages and state,
 *   and the set of nodes connected to it is the membership view that drives
 *   the online flags (dfsm_confchg_fn).
 *
 * Membership: a few voters (default 3), every other node is a standby with a
 * full copy. New nodes join as standby; the leader promotes an online standby
 * whenever voters are missing. Node names and addresses are replicated in a
 * node table next to the raft configuration.
 *
 * All raft and network work runs on one libuv thread. Every connection is
 * TLS 1.3 with the cluster authkey as PSK (rsm-tls.c), on a single address
 * and port per node. Status and membership changes are available over IPC on
 * every node (CFS_IPC_GET_RAFT_STATUS, CFS_IPC_RAFT_CHANGE); changes run on
 * the leader.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /* HAVE_CONFIG_H */

#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <glib.h>
#include <raft.h>
#include <raft/uv.h>
#include <uv.h>

#include "cfs-utils.h"
#include "dfsm-raft.h"
#include "dfsm.h"
#include "rsm-tls.h"
#include "status.h"

#define RAFT_DIR VARLIBDIR "/raft"
#define RAFT_PORT 5420
/* a write that could not be sent at all fails after this */
#define RSM_SEND_TIMEOUT_US (10 * G_USEC_PER_SEC)
/* a sent write that is not applied yet is sent again after this */
#define RSM_RESEND_US (3 * G_USEC_PER_SEC)
#define RSM_TICK_MS 100
#define RSM_CTL_TIMEOUT_US (60 * G_USEC_PER_SEC)
#define RSM_HUBQ_MAX 10000
#define RSM_FRAME_MAX (64 * 1024 * 1024)

#define RSM_HEARTBEAT_MS 50
#define RSM_ELECTION_MS 1000
#define RSM_SNAPSHOT_THRESHOLD 1024
/* keep enough log so that slightly lagging followers get entries, not snapshots */
#define RSM_SNAPSHOT_TRAILING 1024

#define RSM_MAGIC_DCDB 0x52534d31 /* "RSM1" */
#define RSM_MAGIC_NODE 0x4e534d52 /* "RMSN" */
#define RSM_SNAPSHOT_MAGIC 0x32534d52 /* "RMS2" */

#define RSM_RESULT_RING 256

typedef enum { DFSM_KIND_DCDB = 1, DFSM_KIND_HUB = 2 } dfsm_kind_t;

/* side channel frame types */
enum {
    SF_HELLO = 1,     /* follower -> leader: nodeid, pid */
    SF_ENTRY = 2,     /* follower -> leader: raft entry */
    SF_HUB = 3,       /* both: kvstore message */
    SF_VIEW = 4,      /* leader -> follower: membership view */
    SF_STATE = 5,     /* both: kvstore state for a view */
    SF_CTL = 6,       /* follower -> leader: control command */
    SF_CTL_REPLY = 7, /* leader -> follower: control reply */
    SF_PING = 8,      /* both: keepalive */
};

/* a silently dropped connection (no RST) must not keep a node "online" */
#define RSM_PING_US (1 * G_USEC_PER_SEC)
#define RSM_PEER_TIMEOUT_US (3 * G_USEC_PER_SEC)

typedef struct {
    uint32_t magic;
    uint16_t msgtype;
    uint16_t reserved;
    uint32_t nodeid;
    uint32_t pid;
    uint32_t time;
    uint32_t len; /* payload length, entry is padded to 8 bytes */
    uint64_t reqid;
} rsm_hdr_t;

typedef struct {
    guint8 *data;
    size_t len;
    uint64_t reqid;  /* 0: nobody waits for the result */
    gint64 sent;     /* last time it was handed to raft or the leader */
} rsm_out_t;

/* replicated node table entry */
typedef struct {
    uint32_t nodeid;
    int32_t role;
    char name[64];
    char ip[64];
} rsm_node_t;

enum { NODE_SET = 1, NODE_DEL = 2 };

typedef struct {
    uint32_t op;
    rsm_node_t node;
} rsm_node_msg_t;

/* Results of the most recent requests of every node. Replicated state, part
 * of the snapshot: a writer whose entry reached this node inside a snapshot
 * instead of the log still gets its exact result. */
typedef struct {
    uint32_t nodeid;
    uint32_t pid;
    uint64_t reqid;
    int32_t result;
    int32_t processed;
} rsm_result_t;

typedef struct {
    uint32_t nodeid;
    uint32_t next;
    rsm_result_t r[RSM_RESULT_RING];
} rsm_ring_t;

typedef struct {
    char *cluster_name;
    rsm_node_t local;
    GList *bootstrap; /* rsm_node_t*, only used to create a new cluster */
    unsigned voters;  /* desired number of voters, 0 = default */
} rsm_conf_t;

typedef struct side_conn {
    uv_stream_t *stream;
    GByteArray *rbuf;
    uint32_t nodeid;
    uint32_t pid;
    gboolean hello;
    gboolean up; /* our connection to the leader */
    gboolean closing;
    gint64 last_rx;
} side_conn_t;

/* result: 0 or a negative errno; text: the status, or what failed */
typedef void (*ctl_reply_fn)(gpointer ctx, int result, const char *text);

typedef struct {
    uint32_t id;
    gint64 deadline;
    ctl_reply_fn reply;
    gpointer ctx;
} ctl_pending_t;

struct dfsm {
    dfsm_kind_t kind;
    gpointer data;
    char *log_domain;
    dfsm_callbacks_t *callbacks;
    dfsm_raft_snapshot_fn_t snapshot_fn;
    dfsm_raft_restore_fn_t restore_fn;
    uint32_t nodeid;
    uint32_t pid;
    gboolean initialized;
    int evfd;
};

typedef struct {
    rsm_conf_t *conf;
    dfsm_t *dcdb;
    dfsm_t *hub;
    uint32_t nodeid;
    uint32_t pid;

    gboolean started;
    gboolean errormode;

    /* protects results, reqcount, outq, hubq */
    GMutex mutex;
    GCond cond;
    GHashTable *results;
    uint64_t reqcount;
    GQueue *outq;
    GQueue *hubq;

    /* everything below is only touched on the raft thread */
    GThread *thread;
    uv_loop_t loop;
    uv_async_t async;
    uv_timer_t timer;

    struct raft raft;
    struct raft_io io;
    struct raft_uv_transport transport;
    struct raft_fsm fsm;

    /* replicated state */
    GHashTable *nodes; /* nodeid => rsm_node_t */
    GHashTable *rings; /* nodeid => rsm_ring_t */
    uint32_t clinfo_version;

    /* side channel */
    side_conn_t *up;
    raft_id up_target;
    gboolean up_connecting;
    GHashTable *down; /* leader: nodeid => side_conn_t */

    /* kvstore membership view */
    uint32_t view_epoch;
    GArray *view; /* struct cpg_address */

    gboolean was_leader;
    gboolean quorate;

    uint32_t ctl_seq;
    GHashTable *ctl_pending; /* id => ctl_pending_t, forwarded control requests */
    GQueue *ctlq;            /* ipc_req_t, protected by mutex */
    gboolean change_pending; /* a membership change is in flight */
    unsigned voters;         /* desired number of voters */

    gint64 last_ping;
    gint64 last_maintain;

    /* sent entries of local writers that are not applied yet, reqid => rsm_out_t;
     * sent again until applied, apply drops duplicates (see rsm_fsm_apply) */
    GHashTable *inflight;

    /* the status service initialized after the side channel came up: messages
     * and the view received before were dropped, resync (see hub_resync) */
    gint hub_resync_pending;
} rsm_t;

static rsm_t R;

static void rsm_flush(void);
static void rsm_resend(gboolean all);
static void rsm_submit(const guint8 *data, size_t len);
static void side_close(side_conn_t *c);
static void hub_view_changed(void);
static void hub_view_alone(void);

/* ---- configuration and node table ---- */

static gboolean parse_node(gchar **f, int n, rsm_node_t *node) {
    if (n < 4) {
        return FALSE;
    }
    node->nodeid = strtoul(f[1], NULL, 10);
    g_strlcpy(node->name, f[2], sizeof(node->name));
    g_strlcpy(node->ip, f[3], sizeof(node->ip));
    node->role = RAFT_VOTER;
    if (n >= 5) {
        node->role = strcmp(f[4], "voter") == 0     ? RAFT_VOTER
                     : strcmp(f[4], "standby") == 0 ? RAFT_STANDBY
                                                    : RAFT_SPARE;
    }
    return node->nodeid > 0;
}

gboolean dfsm_raft_load_config(const char *filename, const char *nodename) {
    gchar *content = NULL;
    GError *err = NULL;

    if (!g_file_get_contents(filename, &content, NULL, &err)) {
        cfs_critical("unable to read %s: %s", filename, err->message);
        g_error_free(err);
        return FALSE;
    }

    rsm_conf_t *conf = g_new0(rsm_conf_t, 1);

    gchar **lines = g_strsplit(content, "\n", -1);
    for (int i = 0; lines[i]; i++) {
        gchar *line = g_strstrip(lines[i]);
        if (!line[0] || line[0] == '#') {
            continue;
        }

        gchar **all = g_strsplit_set(line, " \t", -1);
        gchar *f[8];
        int n = 0;
        for (int j = 0; all[j] && n < 8; j++) {
            if (all[j][0]) {
                f[n++] = all[j];
            }
        }

        rsm_node_t node = {0};
        if (n == 2 && strcmp(f[0], "voters") == 0) {
            conf->voters = strtoul(f[1], NULL, 10);
        } else if (n == 2 && strcmp(f[0], "cluster") == 0) {
            g_free(conf->cluster_name);
            conf->cluster_name = g_strdup(f[1]);
        } else if (strcmp(f[0], "local") == 0 && parse_node(f, n, &node)) {
            conf->local = node;
        } else if (strcmp(f[0], "member") == 0 && parse_node(f, n, &node)) {
            conf->bootstrap = g_list_append(conf->bootstrap, g_memdup2(&node, sizeof(node)));
        } else {
            cfs_critical("%s: unable to parse line '%s'", filename, line);
        }
        g_strfreev(all);
    }
    g_strfreev(lines);
    g_free(content);

    if (!conf->cluster_name) {
        cfs_critical("%s: no 'cluster <name>' line", filename);
        goto fail;
    }
    if (!conf->local.nodeid) {
        cfs_critical("%s: no 'local <id> <name> <ip>' line", filename);
        goto fail;
    }
    if (strcmp(conf->local.name, nodename) != 0) {
        cfs_critical(
            "%s: local node name '%s' does not match hostname '%s'", filename, conf->local.name,
            nodename
        );
        goto fail;
    }

    R.conf = conf;
    R.voters = conf->voters ? conf->voters : 3;
    R.nodeid = conf->local.nodeid;
    R.nodes = g_hash_table_new_full(g_int_hash, g_int_equal, NULL, g_free);
    R.rings = g_hash_table_new_full(g_int_hash, g_int_equal, NULL, g_free);

    return TRUE;

fail:
    g_free(conf->cluster_name);
    g_list_free_full(conf->bootstrap, g_free);
    g_free(conf);
    return FALSE;
}

static const char *role_name(int role) {
    return role == RAFT_VOTER ? "voter" : role == RAFT_STANDBY ? "standby" : "spare";
}

/* publish the node table to the status module (.members) */
static void publish_clinfo(void) {
    cfs_clinfo_t *clinfo = cfs_clinfo_new(R.conf->cluster_name, ++R.clinfo_version);

    if (g_hash_table_size(R.nodes) > 0) {
        GHashTableIter iter;
        gpointer key, value;
        g_hash_table_iter_init(&iter, R.nodes);
        while (g_hash_table_iter_next(&iter, &key, &value)) {
            rsm_node_t *n = value;
            cfs_clinfo_add_node(
                clinfo, cfs_clnode_new(n->name, n->nodeid, n->role == RAFT_VOTER ? 1 : 0)
            );
        }
    } else {
        /* not yet replicated: what we know locally */
        rsm_node_t *l = &R.conf->local;
        gboolean have_local = FALSE;
        for (GList *it = R.conf->bootstrap; it; it = it->next) {
            rsm_node_t *n = it->data;
            have_local |= n->nodeid == l->nodeid;
            cfs_clinfo_add_node(
                clinfo, cfs_clnode_new(n->name, n->nodeid, n->role == RAFT_VOTER ? 1 : 0)
            );
        }
        if (!have_local) {
            cfs_clinfo_add_node(clinfo, cfs_clnode_new(l->name, l->nodeid, 0));
        }
    }

    cfs_status_set_clinfo(clinfo);
}

static void propose_node(uint32_t op, const rsm_node_t *node) {
    struct {
        rsm_hdr_t hdr;
        rsm_node_msg_t msg;
    } e;
    memset(&e, 0, sizeof(e));
    e.hdr.magic = RSM_MAGIC_NODE;
    e.hdr.nodeid = R.nodeid;
    e.hdr.time = time(NULL);
    e.hdr.len = sizeof(e.msg);
    e.msg.op = op;
    e.msg.node = *node;
    rsm_submit((const guint8 *)&e, sizeof(e));
}

/* ---- apply, commit notification ---- */

static void rsm_apply_cb(struct raft_apply *req, int status, void *result) {
    g_free(req);
    if (status != 0) {
        cfs_debug("raft apply failed: %s", raft_strerror(status));
    }
}

static void rsm_submit(const guint8 *data, size_t len) {
    struct raft_buffer buf;
    buf.len = len;
    buf.base = raft_malloc(len);
    memcpy(buf.base, data, len);

    struct raft_apply *req = g_new0(struct raft_apply, 1);
    int rc = raft_apply(&R.raft, req, &buf, 1, rsm_apply_cb);
    if (rc != 0) {
        cfs_critical("raft_apply failed: %s", raft_strerror(rc));
        raft_free(buf.base);
        g_free(req);
    }
}

/* a local write was applied: hand the result to its writer, stop sending it */
static void rsm_complete(const rsm_result_t *r) {
    g_hash_table_remove(R.inflight, &r->reqid);

    g_mutex_lock(&R.mutex);
    dfsm_result_t *rp = g_hash_table_lookup(R.results, &r->reqid);
    if (rp) {
        rp->result = r->result;
        rp->processed = r->processed;
        g_hash_table_remove(R.results, &r->reqid);
        g_cond_broadcast(&R.cond);
    }
    g_mutex_unlock(&R.mutex);
}

/* after a snapshot restore: complete every local write covered by the snapshot */
static void rsm_complete_from_rings(void) {
    rsm_ring_t *ring = g_hash_table_lookup(R.rings, &R.nodeid);
    if (!ring) {
        return;
    }
    for (int i = 0; i < RSM_RESULT_RING; i++) {
        rsm_result_t *r = &ring->r[i];
        if (r->reqid && r->pid == R.pid) {
            rsm_complete(r);
        }
    }
}

/* result of an already applied request, NULL if it was not applied (yet) */
static rsm_result_t *ring_lookup(rsm_ring_t *ring, uint32_t pid, uint64_t reqid) {
    for (int i = 0; ring && i < RSM_RESULT_RING; i++) {
        if (ring->r[i].reqid == reqid && ring->r[i].pid == pid) {
            return &ring->r[i];
        }
    }
    return NULL;
}

static void apply_node_msg(const rsm_node_msg_t *m) {
    if (m->op == NODE_SET) {
        rsm_node_t *n = g_memdup2(&m->node, sizeof(*n));
        n->name[sizeof(n->name) - 1] = 0;
        n->ip[sizeof(n->ip) - 1] = 0;
        g_hash_table_replace(R.nodes, &n->nodeid, n);
        cfs_message("raft: node %u (%s, %s) is %s", n->nodeid, n->name, n->ip, role_name(n->role));
    } else if (m->op == NODE_DEL) {
        g_hash_table_remove(R.nodes, &m->node.nodeid);
        cfs_message("raft: node %u removed", m->node.nodeid);
    }
    publish_clinfo();
}

static int rsm_fsm_apply(struct raft_fsm *fsm, const struct raft_buffer *buf, void **result) {
    *result = NULL;

    rsm_hdr_t hdr;
    if (buf->len < sizeof(hdr)) {
        cfs_critical("raft: short entry (%zu bytes)", buf->len);
        return 0;
    }
    memcpy(&hdr, buf->base, sizeof(hdr));
    if (sizeof(hdr) + hdr.len > buf->len) {
        cfs_critical("raft: malformed entry");
        return 0;
    }
    const guint8 *msg = (const guint8 *)buf->base + sizeof(hdr);

    if (hdr.magic == RSM_MAGIC_NODE) {
        if (hdr.len == sizeof(rsm_node_msg_t)) {
            rsm_node_msg_t m;
            memcpy(&m, msg, sizeof(m));
            apply_node_msg(&m);
        }
        return 0;
    }
    if (hdr.magic != RSM_MAGIC_DCDB) {
        cfs_critical("raft: unknown entry type %08x", hdr.magic);
        return 0;
    }

    /* a write can be sent more than once (see rsm_resend), apply it only once */
    rsm_ring_t *ring = g_hash_table_lookup(R.rings, &hdr.nodeid);
    if (hdr.reqid && ring_lookup(ring, hdr.pid, hdr.reqid)) {
        cfs_debug("raft: dropping duplicate of request %" PRIu64 " of node %u", hdr.reqid, hdr.nodeid);
        return 0;
    }

    dfsm_t *dfsm = R.dcdb;
    int msg_res = -EBUSY;
    int res = dfsm->callbacks->dfsm_deliver_fn(
        dfsm, dfsm->data, &msg_res, hdr.nodeid, hdr.pid, hdr.msgtype, hdr.time, msg, hdr.len
    );
    if (res < 0) {
        cfs_critical("raft: deliver failed for msgtype %u - entering error mode", hdr.msgtype);
        R.errormode = TRUE;
    }

    if (hdr.reqid) {
        if (!ring) {
            ring = g_new0(rsm_ring_t, 1);
            ring->nodeid = hdr.nodeid;
            g_hash_table_replace(R.rings, &ring->nodeid, ring);
        }
        rsm_result_t *r = &ring->r[ring->next];
        ring->next = (ring->next + 1) % RSM_RESULT_RING;
        r->nodeid = hdr.nodeid;
        r->pid = hdr.pid;
        r->reqid = hdr.reqid;
        r->result = msg_res;
        r->processed = res > 0;

        if (hdr.nodeid == R.nodeid && hdr.pid == R.pid) {
            rsm_complete(r);
        }
    }

    return 0;
}

/* ---- snapshots ---- */

/* layout: magic, rings, nodes, application state */
static int rsm_fsm_snapshot(struct raft_fsm *fsm, struct raft_buffer *bufs[], unsigned *n_bufs) {
    dfsm_t *dfsm = R.dcdb;
    size_t len = 0;

    gpointer data = dfsm->snapshot_fn ? dfsm->snapshot_fn(dfsm->data, &len) : NULL;
    if (!data) {
        cfs_critical("raft: creating snapshot failed");
        return RAFT_NOMEM;
    }

    uint32_t nrings = g_hash_table_size(R.rings);
    uint32_t nnodes = g_hash_table_size(R.nodes);
    size_t hlen = 12 + nrings * sizeof(rsm_ring_t) + nnodes * sizeof(rsm_node_t);

    struct raft_buffer *b = raft_malloc(sizeof(*b));
    b->len = hlen + len;
    b->base = raft_malloc(b->len);

    guint8 *p = b->base;
    uint32_t magic = RSM_SNAPSHOT_MAGIC;
    memcpy(p, &magic, 4);
    memcpy(p + 4, &nrings, 4);
    memcpy(p + 8, &nnodes, 4);
    p += 12;

    GHashTableIter iter;
    gpointer key, value;
    g_hash_table_iter_init(&iter, R.rings);
    while (g_hash_table_iter_next(&iter, &key, &value)) {
        memcpy(p, value, sizeof(rsm_ring_t));
        p += sizeof(rsm_ring_t);
    }
    g_hash_table_iter_init(&iter, R.nodes);
    while (g_hash_table_iter_next(&iter, &key, &value)) {
        memcpy(p, value, sizeof(rsm_node_t));
        p += sizeof(rsm_node_t);
    }
    memcpy(p, data, len);
    g_free(data);

    *bufs = b;
    *n_bufs = 1;

    cfs_message(
        "raft: snapshot at index %" PRIu64 " (%zu bytes)", (uint64_t)raft_last_applied(&R.raft),
        (size_t)b->len
    );
    return 0;
}

static int rsm_fsm_restore(struct raft_fsm *fsm, struct raft_buffer *buf) {
    dfsm_t *dfsm = R.dcdb;
    const guint8 *p = buf->base;
    uint32_t magic = 0, nrings = 0, nnodes = 0;

    if (buf->len >= 12) {
        memcpy(&magic, p, 4);
        memcpy(&nrings, p + 4, 4);
        memcpy(&nnodes, p + 8, 4);
    }
    size_t hlen = 12 + (size_t)nrings * sizeof(rsm_ring_t) + (size_t)nnodes * sizeof(rsm_node_t);
    if (magic != RSM_SNAPSHOT_MAGIC || hlen > buf->len) {
        cfs_critical("raft: malformed snapshot - entering error mode");
        R.errormode = TRUE;
        return RAFT_CORRUPT;
    }

    if (!dfsm->restore_fn || !dfsm->restore_fn(dfsm->data, p + hlen, buf->len - hlen)) {
        cfs_critical("raft: restoring snapshot failed - entering error mode");
        R.errormode = TRUE;
        return RAFT_CORRUPT;
    }

    p += 12;
    g_hash_table_remove_all(R.rings);
    for (uint32_t i = 0; i < nrings; i++, p += sizeof(rsm_ring_t)) {
        rsm_ring_t *ring = g_memdup2(p, sizeof(rsm_ring_t));
        g_hash_table_replace(R.rings, &ring->nodeid, ring);
    }
    g_hash_table_remove_all(R.nodes);
    for (uint32_t i = 0; i < nnodes; i++, p += sizeof(rsm_node_t)) {
        rsm_node_t *n = g_memdup2(p, sizeof(rsm_node_t));
        g_hash_table_replace(R.nodes, &n->nodeid, n);
    }

    publish_clinfo();
    rsm_complete_from_rings();

    /* the fsm owns the buffer on success */
    raft_free(buf->base);
    return 0;
}

void dfsm_raft_set_snapshot_callbacks(
    dfsm_t *dfsm, dfsm_raft_snapshot_fn_t snapshot_fn, dfsm_raft_restore_fn_t restore_fn
) {
    dfsm->snapshot_fn = snapshot_fn;
    dfsm->restore_fn = restore_fn;
}

/* ---- side channel ---- */

static void side_write_done(uv_write_t *req, int status) {
    g_free(req->data);
    g_free(req);
}

static void plain_free_cb(uv_handle_t *h) { raft_free(h); }

/* never closes the connection itself: callers may hold R.mutex */
static void side_write(side_conn_t *c, uint8_t type, const void *a, size_t alen, const void *b,
                       size_t blen) {
    if (!c || c->closing) {
        return;
    }
    uint32_t len = 1 + alen + blen;
    guint8 *frame = g_malloc(4 + len);
    memcpy(frame, &len, 4);
    frame[4] = type;
    if (alen) {
        memcpy(frame + 5, a, alen);
    }
    if (blen) {
        memcpy(frame + 5 + alen, b, blen);
    }

    uv_write_t *req = g_new0(uv_write_t, 1);
    req->data = frame;
    uv_buf_t buf = uv_buf_init((char *)frame, 4 + len);
    if (uv_write(req, c->stream, &buf, 1, side_write_done) < 0) {
        /* the read callback reports the broken connection */
        g_free(frame);
        g_free(req);
    }
}

static void side_close_cb(uv_handle_t *h) {
    side_conn_t *c = h->data;
    raft_free(h);
    g_byte_array_free(c->rbuf, TRUE);
    g_free(c);
}

static void side_close(side_conn_t *c) {
    if (c->closing) {
        return;
    }
    c->closing = TRUE;

    if (c == R.up) {
        R.up = NULL;
        R.up_target = 0;
        cfs_message("raft: lost connection to leader");
        hub_view_alone();
    } else if (c->hello && g_hash_table_lookup(R.down, &c->nodeid) == c) {
        g_hash_table_remove(R.down, &c->nodeid);
        if (raft_state(&R.raft) == RAFT_LEADER) {
            hub_view_changed();
        }
    }

    uv_close((uv_handle_t *)c->stream, side_close_cb);
}

/* -- kvstore hub -- */

typedef struct {
    uint32_t nodeid;
    uint32_t pid;
    uint32_t time;
    uint16_t msgtype;
    uint16_t reserved;
} hub_hdr_t;

static void hub_deliver(const hub_hdr_t *h, const guint8 *msg, size_t len) {
    dfsm_t *hub = R.hub;
    if (!hub || !hub->initialized) {
        return;
    }
    int res = 0;
    hub->callbacks->dfsm_deliver_fn(
        hub, hub->data, &res, h->nodeid, h->pid, h->msgtype, h->time, msg, len
    );
}

static void hub_relay(uint8_t type, const void *a, size_t alen, const void *b, size_t blen,
                      side_conn_t *except) {
    GHashTableIter iter;
    gpointer key, value;
    g_hash_table_iter_init(&iter, R.down);
    while (g_hash_table_iter_next(&iter, &key, &value)) {
        if (value != except) {
            side_write(value, type, a, alen, b, blen);
        }
    }
}

static void hub_set_view(const struct cpg_address *members, size_t n) {
    g_array_set_size(R.view, 0);
    g_array_append_vals(R.view, members, n);

    dfsm_t *hub = R.hub;
    if (!hub || !hub->initialized) {
        return;
    }
    if (hub->callbacks->dfsm_confchg_fn) {
        hub->callbacks->dfsm_confchg_fn(hub, hub->data, members, n);
    }
    /* like CPG: after every membership change (re-announces e.g. nodeip,
     * which cfs_kvstore_sync does not resend) */
    if (hub->callbacks->dfsm_synced_fn) {
        hub->callbacks->dfsm_synced_fn(hub);
    }
}

static void hub_view_alone(void) {
    if (R.view->len == 1) {
        return;
    }
    struct cpg_address self = {.nodeid = R.nodeid, .pid = R.pid};
    hub_set_view(&self, 1);
}

/* our kvstore state (the cluster log) for the current view */
static void hub_send_state(side_conn_t *to) {
    dfsm_t *hub = R.hub;
    if (!hub || !hub->initialized || !hub->callbacks->dfsm_get_state_fn) {
        return;
    }
    unsigned int len = 0;
    gpointer state = hub->callbacks->dfsm_get_state_fn(hub, hub->data, &len);
    if (!state) {
        return;
    }
    uint32_t h[3] = {R.view_epoch, R.nodeid, R.pid};
    if (to) {
        side_write(to, SF_STATE, h, sizeof(h), state, len);
    } else {
        hub_relay(SF_STATE, h, sizeof(h), state, len, NULL);
    }
    g_free(state);
}

/* merge the state of one remote node with ours */
static void hub_process_state(uint32_t nodeid, uint32_t pid, const guint8 *state, size_t len) {
    dfsm_t *hub = R.hub;
    if (!hub || !hub->initialized || !hub->callbacks->dfsm_process_state_update_fn) {
        return;
    }

    unsigned int own_len = 0;
    gpointer own = hub->callbacks->dfsm_get_state_fn(hub, hub->data, &own_len);

    dfsm_sync_info_t *si = g_malloc0(sizeof(dfsm_sync_info_t) + 2 * sizeof(dfsm_node_info_t));
    si->node_count = 2;
    si->nodes[0].nodeid = R.nodeid;
    si->nodes[0].pid = R.pid;
    si->nodes[0].state = own;
    si->nodes[0].state_len = own_len;
    si->nodes[1].nodeid = nodeid;
    si->nodes[1].pid = pid;
    si->nodes[1].state = (gpointer)state;
    si->nodes[1].state_len = len;
    si->local = &si->nodes[0];

    hub->callbacks->dfsm_process_state_update_fn(hub, hub->data, si);
    if (hub->callbacks->dfsm_commit_fn) {
        hub->callbacks->dfsm_commit_fn(hub, hub->data, si);
    }
    if (hub->callbacks->dfsm_cleanup_fn) {
        hub->callbacks->dfsm_cleanup_fn(hub, hub->data, si);
    }

    g_free(si);
    g_free(own);
}

/* leader: membership of the hub changed - announce the new view */
static void hub_view_changed(void) {
    R.view_epoch++;

    GArray *members = g_array_new(FALSE, FALSE, sizeof(struct cpg_address));
    struct cpg_address self = {.nodeid = R.nodeid, .pid = R.pid};
    g_array_append_val(members, self);

    GHashTableIter iter;
    gpointer key, value;
    g_hash_table_iter_init(&iter, R.down);
    while (g_hash_table_iter_next(&iter, &key, &value)) {
        side_conn_t *c = value;
        struct cpg_address a = {.nodeid = c->nodeid, .pid = c->pid};
        g_array_append_val(members, a);
    }

    uint32_t h[2] = {R.view_epoch, members->len};
    uint32_t *list = g_new(uint32_t, 2 * members->len);
    for (guint i = 0; i < members->len; i++) {
        struct cpg_address *a = &g_array_index(members, struct cpg_address, i);
        list[2 * i] = a->nodeid;
        list[2 * i + 1] = a->pid;
    }
    hub_relay(SF_VIEW, h, sizeof(h), list, 8 * members->len, NULL);
    g_free(list);

    hub_set_view((struct cpg_address *)members->data, members->len);
    g_array_free(members, TRUE);

    hub_send_state(NULL);
}

/* the status service is ready now: run confchg/synced and exchange state again */
static void hub_resync(void) {
    if (raft_state(&R.raft) == RAFT_LEADER) {
        hub_view_changed();
    } else if (R.up) {
        /* reconnecting makes the leader announce a new view to everybody */
        side_close(R.up);
    } else {
        struct cpg_address self = {.nodeid = R.nodeid, .pid = R.pid};
        hub_set_view(&self, 1);
    }
}

/* -- control commands -- */

static void ctl_exec(const char *line, ctl_reply_fn reply, gpointer ctx);

typedef struct {
    uint32_t nodeid;
    uint32_t id;
} ctl_remote_t;

/* SF_CTL_REPLY: id, result, text */
static void ctl_reply_remote(gpointer ctx, int result, const char *text) {
    ctl_remote_t *r = ctx;
    side_conn_t *c = g_hash_table_lookup(R.down, &r->nodeid);
    if (c) {
        int32_t h[2] = {r->id, result};
        side_write(c, SF_CTL_REPLY, h, sizeof(h), text, strlen(text) + 1);
    }
    g_free(r);
}

/* only current cluster members may use the side channel: a removed node
 * still has the authkey, but must not be able to submit entries */
static gboolean in_config(uint32_t nodeid) {
    for (unsigned i = 0; i < R.raft.configuration.n; i++) {
        if (R.raft.configuration.servers[i].id == nodeid) {
            return TRUE;
        }
    }
    return FALSE;
}

/* -- side channel receive -- */

static void side_dispatch(side_conn_t *c, uint8_t type, const guint8 *p, size_t len) {
    gboolean leader = raft_state(&R.raft) == RAFT_LEADER;

    /* incoming connections must introduce themselves first */
    if (!c->up && !c->hello && type != SF_HELLO) {
        side_close(c);
        return;
    }

    switch (type) {
    case SF_HELLO: {
        if (c->up || len < 8 || !leader) {
            side_close(c);
            return;
        }
        memcpy(&c->nodeid, p, 4);
        memcpy(&c->pid, p + 4, 4);
        if (!in_config(c->nodeid)) {
            cfs_message("raft: rejecting side channel from non-member %u", c->nodeid);
            side_close(c);
            return;
        }
        side_conn_t *old = g_hash_table_lookup(R.down, &c->nodeid);
        if (old) {
            g_hash_table_remove(R.down, &c->nodeid);
            side_close(old);
        }
        c->hello = TRUE;
        g_hash_table_replace(R.down, &c->nodeid, c);
        hub_view_changed();
        break;
    }
    case SF_ENTRY:
        if (leader) {
            rsm_submit(p, len);
        } else {
            cfs_message("dropping forwarded entry - not leader");
        }
        break;
    case SF_HUB: {
        if (len < sizeof(hub_hdr_t)) {
            break;
        }
        hub_hdr_t h;
        memcpy(&h, p, sizeof(h));
        hub_deliver(&h, p + sizeof(h), len - sizeof(h));
        if (!c->up && leader) {
            hub_relay(SF_HUB, p, len, NULL, 0, c);
        }
        break;
    }
    case SF_VIEW: {
        if (!c->up || len < 8) {
            break;
        }
        uint32_t epoch, n;
        memcpy(&epoch, p, 4);
        memcpy(&n, p + 4, 4);
        if (len < 8 + 8 * (size_t)n) {
            break;
        }
        struct cpg_address *members = g_new0(struct cpg_address, n);
        for (uint32_t i = 0; i < n; i++) {
            memcpy(&members[i].nodeid, p + 8 + 8 * i, 4);
            memcpy(&members[i].pid, p + 12 + 8 * i, 4);
        }
        R.view_epoch = epoch;
        hub_set_view(members, n);
        g_free(members);
        hub_send_state(c);
        break;
    }
    case SF_STATE: {
        if (len < 12) {
            break;
        }
        uint32_t epoch, nodeid, pid;
        memcpy(&epoch, p, 4);
        memcpy(&nodeid, p + 4, 4);
        memcpy(&pid, p + 8, 4);
        if (epoch != R.view_epoch) {
            break; /* stale */
        }
        hub_process_state(nodeid, pid, p + 12, len - 12);
        if (!c->up && leader) {
            hub_relay(SF_STATE, p, len, NULL, 0, c);
        }
        break;
    }
    case SF_CTL: {
        if (c->up || len < 5 || p[len - 1] != 0) {
            break;
        }
        ctl_remote_t *r = g_new0(ctl_remote_t, 1);
        r->nodeid = c->nodeid;
        memcpy(&r->id, p, 4);
        if (!leader) {
            ctl_reply_remote(r, -EAGAIN, "not leader");
            break;
        }
        ctl_exec((const char *)p + 4, ctl_reply_remote, r);
        break;
    }
    case SF_CTL_REPLY: {
        if (!c->up || len < 9 || p[len - 1] != 0) {
            break;
        }
        uint32_t id;
        int32_t result;
        memcpy(&id, p, 4);
        memcpy(&result, p + 4, 4);
        ctl_pending_t *pend = g_hash_table_lookup(R.ctl_pending, &id);
        if (pend) {
            pend->reply(pend->ctx, result, (const char *)p + 8);
            g_hash_table_remove(R.ctl_pending, &id);
        }
        break;
    }
    case SF_PING:
        break;
    default:
        cfs_message("side channel: unknown frame type %u", type);
        side_close(c);
    }
}

static void side_alloc_cb(uv_handle_t *h, size_t suggested, uv_buf_t *buf) {
    buf->base = g_malloc(suggested);
    buf->len = suggested;
}

static void side_read_cb(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf) {
    side_conn_t *c = stream->data;

    if (nread < 0) {
        g_free(buf->base);
        side_close(c);
        return;
    }
    g_byte_array_append(c->rbuf, (guint8 *)buf->base, nread);
    g_free(buf->base);

    while (!c->closing && c->rbuf->len >= 5) {
        uint32_t len;
        memcpy(&len, c->rbuf->data, 4);
        if (len < 1 || len > RSM_FRAME_MAX) {
            side_close(c);
            return;
        }
        if (c->rbuf->len < 4 + len) {
            break;
        }
        c->last_rx = g_get_monotonic_time();
        side_dispatch(c, c->rbuf->data[4], c->rbuf->data + 5, len - 1);
        if (!c->closing) {
            g_byte_array_remove_range(c->rbuf, 0, 4 + len);
        }
    }
}

static side_conn_t *side_new(uv_stream_t *stream, gboolean up) {
    side_conn_t *c = g_new0(side_conn_t, 1);
    c->stream = stream;
    c->rbuf = g_byte_array_new();
    c->up = up;
    c->last_rx = g_get_monotonic_time();
    stream->data = c;
    uv_read_start(stream, side_alloc_cb, side_read_cb);
    return c;
}

/* incoming connection: raft transport or side channel */
static void rsm_accept_cb(void *arg, const rsm_preamble_t *pre, uv_stream_t *plain) {
    if (pre->kind == RSM_KIND_RAFT) {
        rsm_tls_transport_accept(&R.transport, pre, plain);
    } else if (pre->kind == RSM_KIND_SIDE) {
        side_new(plain, FALSE);
    } else {
        uv_close((uv_handle_t *)plain, plain_free_cb);
    }
}

static void up_connect_cb(void *arg, uv_stream_t *plain, int status) {
    raft_id target = GPOINTER_TO_SIZE(arg);
    R.up_connecting = FALSE;

    if (status != 0) {
        cfs_debug("connection to leader failed: %d", status);
        R.up_target = 0;
        return;
    }

    raft_id leader_id = 0;
    const char *leader_addr = NULL;
    raft_leader(&R.raft, &leader_id, &leader_addr);
    if (leader_id != target || raft_state(&R.raft) == RAFT_LEADER) {
        uv_close((uv_handle_t *)plain, plain_free_cb);
        R.up_target = 0;
        return;
    }

    R.up = side_new(plain, TRUE);
    uint32_t hello[2] = {R.nodeid, R.pid};
    side_write(R.up, SF_HELLO, hello, sizeof(hello), NULL, 0);
    cfs_message("raft: connected to leader %" PRIu64, (uint64_t)target);
    rsm_resend(TRUE);
    rsm_flush();
}

/* follower: keep one connection to the current leader */
static void up_check(void) {
    if (raft_state(&R.raft) == RAFT_LEADER) {
        if (R.up) {
            side_close(R.up);
        }
        return;
    }

    raft_id leader_id = 0;
    const char *leader_addr = NULL;
    raft_leader(&R.raft, &leader_id, &leader_addr);

    if (leader_id == 0) {
        if (R.up) {
            side_close(R.up);
        }
        hub_view_alone();
        return;
    }
    if (R.up && R.up_target == leader_id) {
        return;
    }
    if (R.up_connecting) {
        return;
    }
    if (R.up) {
        side_close(R.up);
    }

    char ip[64];
    const char *colon = strrchr(leader_addr, ':');
    if (!colon || colon - leader_addr >= (int)sizeof(ip)) {
        return;
    }
    memcpy(ip, leader_addr, colon - leader_addr);
    ip[colon - leader_addr] = 0;

    rsm_preamble_t pre = {.kind = RSM_KIND_SIDE, .id = R.nodeid};
    g_strlcpy(pre.address, R.conf->local.ip, sizeof(pre.address));

    R.up_target = leader_id;
    R.up_connecting = TRUE;
    if (rsm_tls_connect(
            &R.loop, ip, RAFT_PORT, &pre, up_connect_cb, GSIZE_TO_POINTER((gsize)leader_id)
        ) != 0) {
        R.up_connecting = FALSE;
        R.up_target = 0;
    }
}

/* ---- queues ---- */

static void rsm_out_free(rsm_out_t *out) {
    g_free(out->data);
    g_free(out);
}

/* submit a log entry: on the leader directly, otherwise through the leader */
static void rsm_send_entry(rsm_out_t *out, gboolean leader) {
    if (leader) {
        rsm_submit(out->data, out->len);
    } else {
        side_write(R.up, SF_ENTRY, out->data, out->len, NULL, 0);
    }
    out->sent = g_get_monotonic_time();
}

/* Send local writes that are not applied yet again: the leader may have lost them (leader
 * change, dropped connection) or not. Apply drops the duplicates, so a write is applied
 * exactly once and its writer always gets the real result. With $all, send every write,
 * otherwise only those waiting longer than RSM_RESEND_US. */
static void rsm_resend(gboolean all) {
    gboolean leader = raft_state(&R.raft) == RAFT_LEADER;
    if (!leader && !(R.up && !R.up->closing)) {
        return;
    }
    gint64 now = g_get_monotonic_time();

    GHashTableIter iter;
    gpointer key, value;
    g_hash_table_iter_init(&iter, R.inflight);
    while (g_hash_table_iter_next(&iter, &key, &value)) {
        rsm_out_t *out = value;
        if (all || now - out->sent >= RSM_RESEND_US) {
            rsm_send_entry(out, leader);
        }
    }
}

/* hand queued messages to raft / the leader / the hub members */
static void rsm_flush(void) {
    gboolean leader = raft_state(&R.raft) == RAFT_LEADER;
    gboolean connected = R.up && !R.up->closing;
    GQueue entries = G_QUEUE_INIT;
    GQueue hubmsgs = G_QUEUE_INIT;

    /* only dequeue under the lock - sending may end up in status callbacks */
    g_mutex_lock(&R.mutex);
    if (leader || connected) {
        while (!g_queue_is_empty(R.outq)) {
            g_queue_push_tail(&entries, g_queue_pop_head(R.outq));
        }
        while (!g_queue_is_empty(R.hubq)) {
            g_queue_push_tail(&hubmsgs, g_queue_pop_head(R.hubq));
        }
    } else {
        while (g_queue_get_length(R.hubq) > RSM_HUBQ_MAX) {
            rsm_out_free(g_queue_pop_head(R.hubq));
        }
    }
    g_mutex_unlock(&R.mutex);

    /* once taken from R.outq an entry counts as sent: its writer waits for the result */
    rsm_out_t *out;
    while ((out = g_queue_pop_head(&entries))) {
        rsm_send_entry(out, leader);
        if (out->reqid) {
            g_hash_table_replace(R.inflight, &out->reqid, out);
        } else {
            rsm_out_free(out);
        }
    }
    while ((out = g_queue_pop_head(&hubmsgs))) {
        if (leader) {
            hub_relay(SF_HUB, out->data, out->len, NULL, 0, NULL);
        } else {
            side_write(R.up, SF_HUB, out->data, out->len, NULL, 0);
        }
        rsm_out_free(out);
    }
}

static void ctl_run_queued(void);

static void hub_resync(void);

static void rsm_async_cb(uv_async_t *handle) {
    if (g_atomic_int_compare_and_exchange(&R.hub_resync_pending, 1, 0)) {
        hub_resync();
    }
    ctl_run_queued();
    rsm_flush();
}

static void on_become_leader(void) {
    cfs_message("raft: became leader");
    if (R.up) {
        side_close(R.up);
    }

    /* the first leader of a new cluster publishes the bootstrap members */
    for (GList *it = R.conf->bootstrap; it; it = it->next) {
        rsm_node_t *n = it->data;
        if (!g_hash_table_lookup(R.nodes, &n->nodeid)) {
            propose_node(NODE_SET, n);
        }
    }

    hub_view_changed();
    rsm_resend(TRUE);
}

static void on_lose_leadership(void) {
    cfs_message("raft: lost leadership");
    GList *conns = g_hash_table_get_values(R.down);
    g_hash_table_remove_all(R.down);
    for (GList *l = conns; l; l = l->next) {
        side_close(l->data);
    }
    g_list_free(conns);
    hub_view_alone();
}

static void maintain_voters(void);

static void rsm_timer_cb(uv_timer_t *handle) {
    gboolean leader = raft_state(&R.raft) == RAFT_LEADER;
    if (leader && !R.was_leader) {
        R.was_leader = TRUE;
        on_become_leader();
    } else if (!leader && R.was_leader) {
        R.was_leader = FALSE;
        on_lose_leadership();
    }

    raft_id leader_id = 0;
    const char *leader_addr = NULL;
    raft_leader(&R.raft, &leader_id, &leader_addr);

    gboolean quorate = leader_id != 0;
    if (quorate != R.quorate) {
        R.quorate = quorate;
        cfs_message(
            "raft: %s, leader %" PRIu64 " (%s)", quorate ? "quorate" : "lost quorum",
            (uint64_t)leader_id, raft_state_name(raft_state(&R.raft))
        );
        cfs_set_quorate(quorate, TRUE);
    }

    up_check();

    gint64 now = g_get_monotonic_time();

    /* keepalive in both directions, drop silent peers */
    if (now - R.last_ping >= RSM_PING_US) {
        R.last_ping = now;
        if (R.up) {
            side_write(R.up, SF_PING, NULL, 0, NULL, 0);
        }
        hub_relay(SF_PING, NULL, 0, NULL, 0, NULL);
    }
    if (R.up && now - R.up->last_rx > RSM_PEER_TIMEOUT_US) {
        cfs_message("raft: leader connection timed out");
        side_close(R.up);
    }
    GList *silent = NULL;
    GHashTableIter it;
    gpointer k, v;
    g_hash_table_iter_init(&it, R.down);
    while (g_hash_table_iter_next(&it, &k, &v)) {
        side_conn_t *c = v;
        if (now - c->last_rx > RSM_PEER_TIMEOUT_US || !in_config(c->nodeid)) {
            silent = g_list_prepend(silent, v);
        }
    }
    for (GList *l = silent; l; l = l->next) {
        cfs_message("raft: dropping side channel of node %u", ((side_conn_t *)l->data)->nodeid);
        side_close(l->data);
    }
    g_list_free(silent);

    if (now - R.last_maintain >= 5 * G_USEC_PER_SEC) {
        R.last_maintain = now;
        maintain_voters();
    }

    rsm_resend(FALSE);

    /* expire forwarded control requests */
    GHashTableIter iter;
    gpointer key, value;
    g_hash_table_iter_init(&iter, R.ctl_pending);
    while (g_hash_table_iter_next(&iter, &key, &value)) {
        ctl_pending_t *p = value;
        if (p->deadline < now) {
            p->reply(p->ctx, -ETIMEDOUT, "timeout");
            g_hash_table_iter_remove(&iter);
        }
    }

    rsm_flush();
}

/* ---- membership control (IPC: CFS_IPC_GET_RAFT_STATUS / CFS_IPC_RAFT_CHANGE) ---- */

typedef struct {
    struct raft_change req;
    ctl_reply_fn reply; /* NULL for internal changes (voter maintenance) */
    gpointer ctx;
    rsm_node_t node;
    const char *what;    /* reported on success */
    gboolean adding;     /* part of "add": roll back on failure */
    int rollback_status; /* the error that caused the rollback */
} ctl_op_t;

static int raft_errno(int rc) {
    switch (rc) {
    case 0:
        return 0;
    case RAFT_NOMEM:
        return -ENOMEM;
    case RAFT_NOTLEADER:
    case RAFT_LEADERSHIPLOST:
        return -EAGAIN;
    case RAFT_CANTCHANGE:
        return -EBUSY;
    case RAFT_DUPLICATEID:
    case RAFT_DUPLICATEADDRESS:
        return -EEXIST;
    case RAFT_BADID:
    case RAFT_NOTFOUND:
        return -ENOENT;
    case RAFT_BADROLE:
        return -EINVAL;
    default:
        return -EIO;
    }
}

static void ctl_op_finish(ctl_op_t *op, int status, const char *what) {
    R.change_pending = FALSE;
    if (op->reply) {
        char text[256];
        if (status == 0) {
            g_strlcpy(text, op->what ? op->what : what, sizeof(text));
        } else {
            snprintf(text, sizeof(text), "%s: %s", what, raft_strerror(status));
        }
        op->reply(op->ctx, raft_errno(status), text);
    } else if (status != 0) {
        cfs_message("raft: %s failed: %s", what, raft_strerror(status));
    }
    g_free(op);
}

static void ctl_add_rollback_cb(struct raft_change *req, int status) {
    ctl_op_t *op = req->data;
    if (status == 0) {
        propose_node(NODE_DEL, &op->node);
    }
    op->what = NULL;
    ctl_op_finish(op, op->rollback_status, "add node");
}

/* adding happens in two steps (raft_add, raft_assign) - never leave a half added node */
static void ctl_add_failed(ctl_op_t *op, int status) {
    cfs_message("raft: adding node %u failed, rolling back", op->node.nodeid);
    op->rollback_status = status;
    op->adding = FALSE;
    if (raft_remove(&R.raft, &op->req, op->node.nodeid, ctl_add_rollback_cb) != 0) {
        propose_node(NODE_DEL, &op->node);
        op->what = NULL;
        ctl_op_finish(op, status, "add node");
    }
}

static void ctl_assign_cb(struct raft_change *req, int status) {
    ctl_op_t *op = req->data;
    if (status != 0 && op->adding) {
        ctl_add_failed(op, status);
        return;
    }
    if (status == 0) {
        propose_node(NODE_SET, &op->node);
    }
    ctl_op_finish(op, status, "assign role");
}

static void ctl_add_cb(struct raft_change *req, int status) {
    ctl_op_t *op = req->data;
    if (status != 0) {
        ctl_op_finish(op, status, "add node");
        return;
    }
    /* raft_add() adds a spare. Make it a standby: promoting to voter needs the new node
     * to catch up, but it only starts after the join; maintain_voters() promotes it once
     * it is online. */
    int rc = raft_assign(&R.raft, &op->req, op->node.nodeid, RAFT_STANDBY, ctl_assign_cb);
    if (rc != 0) {
        ctl_add_failed(op, rc);
    }
}

static void ctl_remove_cb(struct raft_change *req, int status) {
    ctl_op_t *op = req->data;
    if (status == 0) {
        propose_node(NODE_DEL, &op->node);
    }
    ctl_op_finish(op, status, "remove node");
}

static gboolean view_has(uint32_t nodeid) {
    for (guint i = 0; i < R.view->len; i++) {
        if (g_array_index(R.view, struct cpg_address, i).nodeid == nodeid) {
            return TRUE;
        }
    }
    return FALSE;
}

static unsigned voter_count(void) {
    unsigned n = 0;
    for (unsigned i = 0; i < R.raft.configuration.n; i++) {
        n += R.raft.configuration.servers[i].role == RAFT_VOTER;
    }
    return n;
}

/* leader: keep R.voters voters, promoting an online standby when one is
 * missing (e.g. after a voter was removed) */
static void maintain_voters(void) {
    if (raft_state(&R.raft) != RAFT_LEADER || R.change_pending || voter_count() >= R.voters) {
        return;
    }
    for (unsigned i = 0; i < R.raft.configuration.n; i++) {
        struct raft_server *srv = &R.raft.configuration.servers[i];
        rsm_node_t *n = g_hash_table_lookup(R.nodes, &(uint32_t){srv->id});
        if (srv->role != RAFT_STANDBY || !n || !view_has(srv->id)) {
            continue;
        }
        ctl_op_t *op = g_new0(ctl_op_t, 1);
        op->req.data = op;
        op->node = *n;
        op->node.role = RAFT_VOTER;
        cfs_message("raft: promoting node %u (%s) to voter", n->nodeid, n->name);
        if (raft_assign(&R.raft, &op->req, srv->id, RAFT_VOTER, ctl_assign_cb) == 0) {
            R.change_pending = TRUE;
        } else {
            g_free(op);
        }
        return;
    }
}

static void json_escape(GString *s, const char *str) {
    g_string_append_c(s, '"');
    for (const char *p = str; *p; p++) {
        if (*p == '"' || *p == '\\') {
            g_string_append_c(s, '\\');
        }
        if ((unsigned char)*p >= 0x20) {
            g_string_append_c(s, *p);
        }
    }
    g_string_append_c(s, '"');
}

static void ctl_status(GString *s) {
    raft_id leader_id = 0;
    const char *leader_addr = NULL;
    raft_leader(&R.raft, &leader_id, &leader_addr);

    g_string_append(s, "{\"cluster\":");
    json_escape(s, R.conf->cluster_name);
    g_string_append_printf(
        s,
        ",\"nodeid\":%u,\"state\":\"%s\",\"term\":%" PRIu64 ",\"leader\":%" PRIu64
        ",\"quorate\":%d,\"voters\":%u,\"last_index\":%" PRIu64 ",\"applied_index\":%" PRIu64
        ",\"members\":[",
        R.nodeid, raft_state_name(raft_state(&R.raft)), (uint64_t)R.raft.current_term,
        (uint64_t)leader_id, R.quorate ? 1 : 0, R.voters, (uint64_t)raft_last_index(&R.raft),
        (uint64_t)raft_last_applied(&R.raft)
    );
    for (unsigned i = 0; i < R.raft.configuration.n; i++) {
        struct raft_server *srv = &R.raft.configuration.servers[i];
        rsm_node_t *n = g_hash_table_lookup(R.nodes, &(uint32_t){srv->id});
        g_string_append_printf(s, "%s{\"id\":%" PRIu64 ",\"name\":", i ? "," : "", (uint64_t)srv->id);
        json_escape(s, n ? n->name : "");
        g_string_append(s, ",\"ip\":");
        json_escape(s, n ? n->ip : "");
        g_string_append_printf(
            s, ",\"role\":\"%s\",\"online\":%d}", role_name(srv->role), view_has(srv->id) ? 1 : 0
        );
    }
    g_string_append(s, "]}\n");
}

/* commands: status | add <id> <name> <ip> | remove <id> */
static void ctl_exec(const char *line, ctl_reply_fn reply, gpointer ctx) {
    gchar **argv = NULL;
    gint argc = 0;
    if (!g_shell_parse_argv(line, &argc, &argv, NULL) || argc < 1) {
        reply(ctx, -EINVAL, "empty command");
        g_strfreev(argv);
        return;
    }

    if (strcmp(argv[0], "status") == 0) {
        GString *s = g_string_new(NULL);
        ctl_status(s);
        reply(ctx, 0, s->str);
        g_string_free(s, TRUE);
        g_strfreev(argv);
        return;
    }

    gboolean is_add = strcmp(argv[0], "add") == 0;
    gboolean is_remove = strcmp(argv[0], "remove") == 0;
    if (!is_add && !is_remove) {
        reply(ctx, -EINVAL, "unknown command");
        g_strfreev(argv);
        return;
    }

    if (raft_state(&R.raft) != RAFT_LEADER) {
        /* run it on the leader */
        if (!R.up || R.up->closing || reply == ctl_reply_remote) {
            reply(ctx, -EAGAIN, "no connection to the leader");
        } else {
            ctl_pending_t *p = g_new0(ctl_pending_t, 1);
            p->id = ++R.ctl_seq;
            p->deadline = g_get_monotonic_time() + RSM_CTL_TIMEOUT_US;
            p->reply = reply;
            p->ctx = ctx;
            g_hash_table_replace(R.ctl_pending, &p->id, p);
            side_write(R.up, SF_CTL, &p->id, 4, line, strlen(line) + 1);
        }
        g_strfreev(argv);
        return;
    }

    ctl_op_t *op = g_new0(ctl_op_t, 1);
    op->reply = reply;
    op->ctx = ctx;
    op->req.data = op;
    int rc;

    if (is_add) {
        if (argc != 4) {
            reply(ctx, -EINVAL, "usage: add <id> <name> <ip>");
            g_free(op);
            g_strfreev(argv);
            return;
        }
        op->node.nodeid = strtoul(argv[1], NULL, 10);
        g_strlcpy(op->node.name, argv[2], sizeof(op->node.name));
        g_strlcpy(op->node.ip, argv[3], sizeof(op->node.ip));
        /* joins as standby, maintain_voters() promotes it if voters are missing */
        op->node.role = RAFT_STANDBY;
        op->adding = TRUE;
        op->what = voter_count() < R.voters ? "node added, becomes voter once online"
                                            : "node added as standby";

        char address[128];
        snprintf(address, sizeof(address), "%s:%d", op->node.ip, RAFT_PORT);
        rc = raft_add(&R.raft, &op->req, op->node.nodeid, address, ctl_add_cb);
        if (rc == 0) {
            R.change_pending = TRUE;
            /* name and address for .members */
            propose_node(NODE_SET, &op->node);
        } else {
            ctl_op_finish(op, rc, "add node");
        }
    } else {
        uint32_t nodeid = argc > 1 ? strtoul(argv[1], NULL, 10) : 0;
        rsm_node_t *known = g_hash_table_lookup(R.nodes, &nodeid);
        if (!nodeid || !known) {
            reply(ctx, -ENOENT, "unknown node id");
            g_free(op);
            g_strfreev(argv);
            return;
        }
        op->node = *known;
        rc = raft_remove(&R.raft, &op->req, nodeid, ctl_remove_cb);
        if (rc == 0) {
            R.change_pending = TRUE;
        } else {
            ctl_op_finish(op, rc, "remove node");
        }
    }

    g_strfreev(argv);
}

/* IPC requests are run on the raft thread. The IPC thread either waits for the reply
 * (status, answered locally) or gets it through a callback (membership changes, which
 * can take long: they run on the leader and wait for the raft configuration change). */
typedef struct {
    gchar *line;
    GString *out;
    int result;
    gboolean done;
    gint refs;
    dfsm_raft_change_cb cb; /* called on the raft thread, instead of waking a waiter */
    gpointer cb_data;
} ipc_req_t;

static void ipc_req_unref(ipc_req_t *req) {
    if (g_atomic_int_dec_and_test(&req->refs)) {
        g_free(req->line);
        g_string_free(req->out, TRUE);
        g_free(req);
    }
}

static void ctl_reply_ipc(gpointer ctx, int result, const char *text) {
    ipc_req_t *req = ctx;
    if (result < 0) {
        cfs_critical("raft: '%s' failed: %s", req->line, text);
    }
    if (req->cb) {
        req->cb(req->cb_data, result);
        ipc_req_unref(req);
        return;
    }
    g_mutex_lock(&R.mutex);
    req->result = result;
    g_string_assign(req->out, text);
    req->done = TRUE;
    g_cond_broadcast(&R.cond);
    g_mutex_unlock(&R.mutex);
    ipc_req_unref(req);
}

static void ctl_run_queued(void) {
    GQueue reqs = G_QUEUE_INIT;
    g_mutex_lock(&R.mutex);
    while (!g_queue_is_empty(R.ctlq)) {
        g_queue_push_tail(&reqs, g_queue_pop_head(R.ctlq));
    }
    g_mutex_unlock(&R.mutex);

    ipc_req_t *req;
    while ((req = g_queue_pop_head(&reqs))) {
        ctl_exec(req->line, ctl_reply_ipc, req);
    }
}

/* run a control command on the raft thread and wait for its result */
static int ctl_call(const char *line, GString *out) {
    if (!R.started || !R.thread) {
        return -EAGAIN;
    }

    ipc_req_t *req = g_new0(ipc_req_t, 1);
    req->line = g_strdup(line);
    req->out = g_string_new(NULL);
    req->refs = 2; /* waiter + raft thread */

    gint64 deadline = g_get_monotonic_time() + RSM_CTL_TIMEOUT_US + G_USEC_PER_SEC;
    int res = -ETIMEDOUT;

    g_mutex_lock(&R.mutex);
    g_queue_push_tail(R.ctlq, req);
    uv_async_send(&R.async);
    while (!req->done) {
        if (!g_cond_wait_until(&R.cond, &R.mutex, deadline)) {
            break;
        }
    }
    if (req->done) {
        res = req->result;
        if (out && res == 0) {
            g_string_assign(out, req->out->str);
        }
    }
    g_mutex_unlock(&R.mutex);

    ipc_req_unref(req);
    return res;
}

int dfsm_raft_get_status(GString *out) { return ctl_call("status", out); }

int dfsm_raft_change(const char *cmd, dfsm_raft_change_cb cb, gpointer data) {
    g_return_val_if_fail(cmd != NULL && cb != NULL, -EINVAL);

    if (strncmp(cmd, "add ", 4) != 0 && strncmp(cmd, "remove ", 7) != 0) {
        return -EINVAL;
    }
    if (!R.started || !R.thread) {
        return -EAGAIN;
    }

    ipc_req_t *req = g_new0(ipc_req_t, 1);
    req->line = g_strdup(cmd);
    req->out = g_string_new(NULL);
    req->refs = 1; /* raft thread */
    req->cb = cb;
    req->cb_data = data;

    g_mutex_lock(&R.mutex);
    g_queue_push_tail(R.ctlq, req);
    g_mutex_unlock(&R.mutex);
    uv_async_send(&R.async);

    return 0;
}

/* ---- startup ---- */

static gpointer rsm_thread(gpointer data) {
    uv_run(&R.loop, UV_RUN_DEFAULT);
    return NULL;
}

static gboolean rsm_start(void) {
    int rc;
    char address[128];
    rsm_node_t *local = &R.conf->local;

    if (!rsm_tls_init(RAFT_AUTHKEY)) {
        return FALSE;
    }

    g_mkdir_with_parents(RAFT_DIR, 0700);
    g_mkdir_with_parents(RUNDIR, 0755);
    snprintf(address, sizeof(address), "%s:%d", local->ip, RAFT_PORT);

    R.pid = getpid();
    R.view = g_array_new(FALSE, FALSE, sizeof(struct cpg_address));
    R.down = g_hash_table_new(g_int_hash, g_int_equal);
    R.ctl_pending = g_hash_table_new_full(g_int_hash, g_int_equal, NULL, g_free);
    R.inflight =
        g_hash_table_new_full(g_int64_hash, g_int64_equal, NULL, (GDestroyNotify)rsm_out_free);

    uv_loop_init(&R.loop);

    rsm_tls_transport_init(&R.transport, &R.loop);
    R.io.version = 2;
    if ((rc = raft_uv_init(&R.io, &R.loop, RAFT_DIR, &R.transport)) != 0) {
        cfs_critical("raft_uv_init failed: %s", raft_strerror(rc));
        return FALSE;
    }

    /* ask libraft to send a new commit index to the followers right away, not with the
     * next heartbeat: a writer on a follower waits until its entry is applied locally.
     * Ignored by libraft versions without this option. */
    g_setenv("LIBRAFT_PUSH_COMMIT", "1", TRUE);

    R.fsm.version = 1;
    R.fsm.data = &R;
    R.fsm.apply = rsm_fsm_apply;
    R.fsm.snapshot = rsm_fsm_snapshot;
    R.fsm.restore = rsm_fsm_restore;

    if ((rc = raft_init(&R.raft, &R.io, &R.fsm, local->nodeid, address)) != 0) {
        cfs_critical("raft_init failed: %s", raft_strerror(rc));
        return FALSE;
    }

    raft_set_heartbeat_timeout(&R.raft, RSM_HEARTBEAT_MS);
    raft_set_election_timeout(&R.raft, RSM_ELECTION_MS);
    raft_set_pre_vote(&R.raft, true);
    raft_set_snapshot_threshold(&R.raft, RSM_SNAPSHOT_THRESHOLD);
    raft_set_snapshot_trailing(&R.raft, RSM_SNAPSHOT_TRAILING);

    if (R.conf->bootstrap) {
        struct raft_configuration conf;
        raft_configuration_init(&conf);
        for (GList *l = R.conf->bootstrap; l; l = l->next) {
            rsm_node_t *n = l->data;
            char addr[128];
            snprintf(addr, sizeof(addr), "%s:%d", n->ip, RAFT_PORT);
            raft_configuration_add(&conf, n->nodeid, addr, n->role);
        }
        rc = raft_bootstrap(&R.raft, &conf);
        raft_configuration_close(&conf);
        if (rc != 0 && rc != RAFT_CANTBOOTSTRAP) {
            cfs_critical("raft_bootstrap failed: %s", raft_strerror(rc));
            return FALSE;
        }
    }

    publish_clinfo();

    if ((rc = rsm_tls_listen(&R.loop, local->ip, RAFT_PORT, rsm_accept_cb, NULL)) < 0) {
        cfs_critical("unable to listen on %s:%d: %s", local->ip, RAFT_PORT, uv_strerror(rc));
        return FALSE;
    }

    if ((rc = raft_start(&R.raft)) != 0) {
        cfs_critical("raft_start failed: %s", raft_strerror(rc));
        return FALSE;
    }

    uv_async_init(&R.loop, &R.async, rsm_async_cb);
    uv_timer_init(&R.loop, &R.timer);
    uv_timer_start(&R.timer, rsm_timer_cb, RSM_TICK_MS, RSM_TICK_MS);

    cfs_message(
        "raft started: id %u address %s%s", local->nodeid, address,
        R.conf->bootstrap ? "" : " (joining)"
    );

    R.thread = g_thread_new("raft", rsm_thread, NULL);

    return TRUE;
}

/* ---- dfsm.h API ---- */

dfsm_t *dfsm_new(
    gpointer data,
    const char *group_name,
    const char *log_domain,
    guint32 protocol_version,
    dfsm_callbacks_t *callbacks
) {
    g_return_val_if_fail(callbacks != NULL, NULL);
    g_return_val_if_fail(callbacks->dfsm_deliver_fn != NULL, NULL);

    if (!R.conf) {
        cfs_critical("dfsm_new: raft configuration not loaded");
        return NULL;
    }

    dfsm_t *dfsm = g_new0(dfsm_t, 1);
    dfsm->data = data;
    dfsm->log_domain = g_strdup(log_domain);
    dfsm->callbacks = callbacks;
    dfsm->nodeid = R.nodeid;
    dfsm->pid = getpid();
    dfsm->evfd = -1;

    if (strcmp(group_name, "pve_dcdb_v1") == 0) {
        dfsm->kind = DFSM_KIND_DCDB;
        R.dcdb = dfsm;
    } else {
        dfsm->kind = DFSM_KIND_HUB;
        R.hub = dfsm;
    }

    if (!R.results) {
        g_mutex_init(&R.mutex);
        g_cond_init(&R.cond);
        R.results = g_hash_table_new(g_int64_hash, g_int64_equal);
        /* request ids identify writes in the replicated result rings together with the
         * pid, which can repeat after a restart: start at a random point */
        R.reqcount = (uint64_t)g_random_int() << 32;
        R.outq = g_queue_new();
        R.hubq = g_queue_new();
        R.ctlq = g_queue_new();
    }

    return dfsm;
}

void dfsm_destroy(dfsm_t *dfsm) {
    /* the raft thread lives for the whole process lifetime */
}

cs_error_t dfsm_initialize(dfsm_t *dfsm, int *fd) {
    g_return_val_if_fail(dfsm != NULL, CS_ERR_INVALID_PARAM);
    g_return_val_if_fail(fd != NULL, CS_ERR_INVALID_PARAM);

    if (!dfsm->initialized) {
        /* pid may change after daemonizing */
        dfsm->pid = getpid();
        if (!R.started) {
            if (!R.dcdb) {
                return CS_ERR_TRY_AGAIN;
            }
            R.started = TRUE;
            if (!rsm_start()) {
                R.errormode = TRUE;
                return CS_ERR_LIBRARY;
            }
        }
        dfsm->evfd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
        dfsm->initialized = TRUE;
        if (dfsm->kind == DFSM_KIND_HUB) {
            g_atomic_int_set(&R.hub_resync_pending, 1);
            uv_async_send(&R.async);
        }
    }

    *fd = dfsm->evfd;
    return CS_OK;
}

gboolean dfsm_finalize(dfsm_t *dfsm) { return TRUE; }

cs_error_t dfsm_join(dfsm_t *dfsm) { return CS_OK; }

cs_error_t dfsm_leave(dfsm_t *dfsm) { return CS_OK; }

cs_error_t dfsm_dispatch(dfsm_t *dfsm, cs_dispatch_flags_t dispatch_types) {
    uint64_t v;
    if (read(dfsm->evfd, &v, sizeof(v)) < 0) {
        /* nothing to do */
    }
    return CS_OK;
}

gboolean dfsm_restartable(dfsm_t *dfsm) { return !R.errormode; }

gboolean dfsm_is_initialized(dfsm_t *dfsm) { return dfsm->initialized; }

void dfsm_set_errormode(dfsm_t *dfsm) {
    cfs_critical("raft: entering error mode");
    R.errormode = TRUE;
}

cs_error_t dfsm_send_message(dfsm_t *dfsm, uint16_t msgtype, struct iovec *iov, int len) {
    return dfsm_send_message_sync(dfsm, msgtype, iov, len, NULL);
}

static cs_error_t hub_send(dfsm_t *dfsm, uint16_t msgtype, struct iovec *iov, int len) {
    size_t payload = 0;
    for (int i = 0; i < len; i++) {
        payload += iov[i].iov_len;
    }

    rsm_out_t *out = g_new0(rsm_out_t, 1);
    out->len = sizeof(hub_hdr_t) + payload;
    out->data = g_malloc(out->len);

    hub_hdr_t h = {
        .nodeid = R.nodeid,
        .pid = dfsm->pid,
        .time = time(NULL),
        .msgtype = msgtype,
    };
    memcpy(out->data, &h, sizeof(h));
    guint8 *p = out->data + sizeof(h);
    for (int i = 0; i < len; i++) {
        memcpy(p, iov[i].iov_base, iov[i].iov_len);
        p += iov[i].iov_len;
    }

    g_mutex_lock(&R.mutex);
    g_queue_push_tail(R.hubq, out);
    g_mutex_unlock(&R.mutex);
    uv_async_send(&R.async);

    return CS_OK;
}

cs_error_t dfsm_send_message_sync(
    dfsm_t *dfsm, uint16_t msgtype, struct iovec *iov, int len, dfsm_result_t *rp
) {
    g_return_val_if_fail(dfsm != NULL, CS_ERR_INVALID_PARAM);
    g_return_val_if_fail(!len || iov != NULL, CS_ERR_INVALID_PARAM);

    if (!dfsm->initialized || R.errormode) {
        return CS_ERR_NOT_EXIST;
    }

    if (dfsm->kind == DFSM_KIND_HUB) {
        return hub_send(dfsm, msgtype, iov, len);
    }

    size_t payload = 0;
    for (int i = 0; i < len; i++) {
        payload += iov[i].iov_len;
    }
    size_t total = (sizeof(rsm_hdr_t) + payload + 7) & ~(size_t)7;

    rsm_out_t *out = g_new0(rsm_out_t, 1);
    out->data = g_malloc0(total);
    out->len = total;

    rsm_hdr_t hdr = {
        .magic = RSM_MAGIC_DCDB,
        .msgtype = msgtype,
        .nodeid = R.nodeid,
        .pid = dfsm->pid,
        .time = time(NULL),
        .len = payload,
    };

    guint8 *p = out->data + sizeof(hdr);
    for (int i = 0; i < len; i++) {
        memcpy(p, iov[i].iov_base, iov[i].iov_len);
        p += iov[i].iov_len;
    }

    gint64 deadline = g_get_monotonic_time() + RSM_SEND_TIMEOUT_US;

    g_mutex_lock(&R.mutex);

    if (rp) {
        hdr.reqid = ++R.reqcount;
        out->reqid = hdr.reqid;
        rp->msgcount = hdr.reqid;
        rp->processed = 0;
        g_hash_table_replace(R.results, &rp->msgcount, rp);
    }
    memcpy(out->data, &hdr, sizeof(hdr));

    g_queue_push_tail(R.outq, out);
    uv_async_send(&R.async);

    if (!rp) {
        g_mutex_unlock(&R.mutex);
        return CS_OK;
    }

    /* Not sent within the timeout (no leader): take it back, it can never be applied.
     * Once sent, the outcome is only known when it is applied here: wait for that, the
     * raft thread sends it again as needed. */
    while (g_hash_table_contains(R.results, &rp->msgcount)) {
        if (deadline && !g_cond_wait_until(&R.cond, &R.mutex, deadline)) {
            if (g_queue_remove(R.outq, out)) {
                g_hash_table_remove(R.results, &rp->msgcount);
                g_mutex_unlock(&R.mutex);
                rsm_out_free(out);
                cfs_dom_critical(dfsm->log_domain, "raft: message %u not sent - no leader", msgtype);
                rp->result = -ETIMEDOUT;
                return CS_ERR_TIMEOUT;
            }
            cfs_dom_message(
                dfsm->log_domain, "raft: message %u sent but not applied yet - waiting", msgtype
            );
            deadline = 0;
        } else if (!deadline) {
            g_cond_wait(&R.cond, &R.mutex);
        }
    }

    g_mutex_unlock(&R.mutex);

    return rp->processed ? CS_OK : CS_ERR_FAILED_OPERATION;
}

cs_error_t dfsm_send_update(dfsm_t *dfsm, struct iovec *iov, unsigned int len) {
    return CS_ERR_NOT_SUPPORTED;
}

cs_error_t dfsm_send_update_complete(dfsm_t *dfsm) { return CS_ERR_NOT_SUPPORTED; }

gboolean dfsm_lowest_nodeid(dfsm_t *dfsm) {
    /* only called from the apply path, i.e. on the raft thread */
    return raft_state(&R.raft) == RAFT_LEADER;
}

gboolean dfsm_nodeid_is_local(dfsm_t *dfsm, uint32_t nodeid, uint32_t pid) {
    return nodeid == dfsm->nodeid && pid == dfsm->pid;
}

cs_error_t dfsm_verify_request(dfsm_t *dfsm) { return CS_OK; }

/* ---- cfs service glue ---- */

static gboolean service_dfsm_finalize(cfs_service_t *service, gpointer context) { return TRUE; }

static int service_dfsm_initialize(cfs_service_t *service, gpointer context) {
    dfsm_t *dfsm = context;
    int fd = -1;

    if (!dfsm_restartable(dfsm)) {
        return -1;
    }
    if (dfsm_initialize(dfsm, &fd) != CS_OK) {
        return -1;
    }
    return fd;
}

static gboolean service_dfsm_dispatch(cfs_service_t *service, gpointer context) {
    dfsm_dispatch(context, CS_DISPATCH_ONE);
    return TRUE;
}

static cfs_service_callbacks_t cfs_dfsm_callbacks = {
    .cfs_service_initialize_fn = service_dfsm_initialize,
    .cfs_service_finalize_fn = service_dfsm_finalize,
    .cfs_service_dispatch_fn = service_dfsm_dispatch,
};

cfs_service_t *service_dfsm_new(dfsm_t *dfsm) {
    g_return_val_if_fail(dfsm != NULL, NULL);
    return cfs_service_new(&cfs_dfsm_callbacks, dfsm->log_domain, dfsm);
}

void service_dfsm_destroy(cfs_service_t *service) { g_free(service); }
