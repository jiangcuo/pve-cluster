#ifndef _PVE_RSM_TLS_H_
#define _PVE_RSM_TLS_H_

#include <glib.h>
#include <stdint.h>
#include <uv.h>

/* Every connection between the pmxcfs raft nodes is TLS 1.3 with an external
 * pre-shared key (the cluster authkey) and starts with a preamble that tells
 * the listener what the connection is for. The plaintext is handed to the
 * user as a uv_stream_t (one end of a socketpair), allocated with raft_malloc;
 * the user uv_close()s it and releases it with raft_free. */

#define RSM_KIND_RAFT 1 /* raft transport */
#define RSM_KIND_SIDE 2 /* forwarding / status hub / control */

typedef struct {
    uint32_t kind;
    uint64_t id;      /* sender raft id */
    char address[64]; /* sender raft address */
} rsm_preamble_t;

typedef void (*rsm_tls_connect_cb)(void *arg, uv_stream_t *plain, int status);
typedef void (*rsm_tls_accept_cb)(void *arg, const rsm_preamble_t *pre, uv_stream_t *plain);

gboolean rsm_tls_init(const char *keyfile);

int rsm_tls_connect(
    uv_loop_t *loop,
    const char *ip,
    int port,
    const rsm_preamble_t *pre,
    rsm_tls_connect_cb cb,
    void *arg
);

int rsm_tls_listen(uv_loop_t *loop, const char *ip, int port, rsm_tls_accept_cb cb, void *arg);

/* raft_uv_transport on top of rsm_tls, accepting connections from the
 * listener created with rsm_tls_listen (see rsm_tls_transport_accept) */
struct raft_uv_transport;
int rsm_tls_transport_init(struct raft_uv_transport *t, uv_loop_t *loop);
void rsm_tls_transport_accept(
    struct raft_uv_transport *t, const rsm_preamble_t *pre, uv_stream_t *plain
);

#endif /* _PVE_RSM_TLS_H_ */
