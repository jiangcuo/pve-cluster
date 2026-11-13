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

/* TLS 1.3 external-PSK connections for the pmxcfs raft backend.
 *
 * libraft (and our side channel) want a plain uv_stream_t. We run TLS on the
 * TCP connection with memory BIOs and hand the user one end of a socketpair:
 *
 *   peer <== TCP/TLS ==> [tls_conn] <== socketpair (plaintext) ==> user
 *
 * The PSK is derived from the cluster authkey file (like corosync's authkey,
 * stored locally, not in /etc/pve).
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /* HAVE_CONFIG_H */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <glib.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <raft.h>
#include <raft/uv.h>
#include <uv.h>

#include "cfs-utils.h"
#include "rsm-tls.h"

#define PSK_IDENTITY "pmxcfs"
#define PREAMBLE_MAGIC 0x31415250 /* "PRA1" */
#define HANDSHAKE_TIMEOUT_MS 5000

typedef struct {
    uint32_t magic;
    uint32_t kind;
    uint64_t id;
    char address[64];
} wire_preamble_t;

static SSL_CTX *client_ctx;
static SSL_CTX *server_ctx;
static unsigned char psk[32];

typedef struct tls_conn {
    uv_loop_t *loop;
    uv_tcp_t tcp;
    uv_connect_t creq;
    uv_timer_t timer;
    uv_pipe_t inner; /* our end of the socketpair */
    gboolean inner_open;

    SSL *ssl;
    BIO *rbio;
    BIO *wbio;

    gboolean server;
    gboolean established;
    gboolean opened; /* plaintext stream handed to the user */
    gboolean notified;
    gboolean closing;
    int refs;

    GByteArray *pre; /* server: preamble bytes received so far */
    wire_preamble_t wpre; /* client: preamble to send */

    rsm_tls_connect_cb ccb;
    rsm_tls_accept_cb acb;
    void *arg;
} tls_conn_t;

/* ---- PSK ---- */

static SSL_SESSION *psk_session(SSL *ssl) {
    static const unsigned char aes128gcmsha256[] = {0x13, 0x01};
    const SSL_CIPHER *cipher = SSL_CIPHER_find(ssl, aes128gcmsha256);
    SSL_SESSION *sess = SSL_SESSION_new();

    if (!cipher || !sess || !SSL_SESSION_set1_master_key(sess, psk, sizeof(psk)) ||
        !SSL_SESSION_set_cipher(sess, cipher) ||
        !SSL_SESSION_set_protocol_version(sess, TLS1_3_VERSION)) {
        SSL_SESSION_free(sess);
        return NULL;
    }
    return sess;
}

static int psk_use_session_cb(
    SSL *ssl, const EVP_MD *md, const unsigned char **id, size_t *idlen, SSL_SESSION **sessptr
) {
    SSL_SESSION *sess = psk_session(ssl);
    if (!sess) {
        return 0;
    }
    if (md && md != SSL_CIPHER_get_handshake_digest(SSL_SESSION_get0_cipher(sess))) {
        SSL_SESSION_free(sess);
        *sessptr = NULL;
        return 1;
    }
    *id = (const unsigned char *)PSK_IDENTITY;
    *idlen = strlen(PSK_IDENTITY);
    *sessptr = sess;
    return 1;
}

static int psk_find_session_cb(
    SSL *ssl, const unsigned char *id, size_t idlen, SSL_SESSION **sessptr
) {
    if (idlen != strlen(PSK_IDENTITY) || memcmp(id, PSK_IDENTITY, idlen) != 0) {
        *sessptr = NULL;
        return 1;
    }
    *sessptr = psk_session(ssl);
    return *sessptr ? 1 : 0;
}

static SSL_CTX *tls_ctx_new(gboolean server) {
    SSL_CTX *ctx = SSL_CTX_new(server ? TLS_server_method() : TLS_client_method());
    if (!ctx) {
        return NULL;
    }
    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
    SSL_CTX_set_ciphersuites(ctx, "TLS_AES_128_GCM_SHA256");
    if (server) {
        SSL_CTX_set_psk_find_session_callback(ctx, psk_find_session_cb);
        SSL_CTX_set_num_tickets(ctx, 0);
    } else {
        SSL_CTX_set_psk_use_session_callback(ctx, psk_use_session_cb);
    }
    return ctx;
}

gboolean rsm_tls_init(const char *keyfile) {
    gchar *key = NULL;
    gsize keylen = 0;
    GError *err = NULL;

    if (!g_file_get_contents(keyfile, &key, &keylen, &err)) {
        cfs_critical("unable to read authkey %s: %s", keyfile, err->message);
        g_error_free(err);
        return FALSE;
    }
    if (keylen < 16) {
        cfs_critical("authkey %s too short", keyfile);
        g_free(key);
        return FALSE;
    }

    unsigned int len = sizeof(psk);
    EVP_Digest(key, keylen, psk, &len, EVP_sha256(), NULL);
    memset(key, 0, keylen);
    g_free(key);

    client_ctx = tls_ctx_new(FALSE);
    server_ctx = tls_ctx_new(TRUE);
    if (!client_ctx || !server_ctx) {
        cfs_critical("unable to create TLS context");
        return FALSE;
    }
    return TRUE;
}

/* ---- connection ---- */

static void conn_unref(tls_conn_t *c) {
    if (--c->refs > 0) {
        return;
    }
    SSL_free(c->ssl);
    if (c->pre) {
        g_byte_array_free(c->pre, TRUE);
    }
    g_free(c);
}

static void conn_handle_closed(uv_handle_t *h) { conn_unref(h->data); }

static void conn_close(tls_conn_t *c) {
    if (c->closing) {
        return;
    }
    c->closing = TRUE;

    if (!c->server && !c->notified) {
        c->notified = TRUE;
        c->ccb(c->arg, NULL, -ECONNABORTED);
    }

    uv_close((uv_handle_t *)&c->timer, conn_handle_closed);
    uv_close((uv_handle_t *)&c->tcp, conn_handle_closed);
    if (c->inner_open) {
        uv_close((uv_handle_t *)&c->inner, conn_handle_closed);
    }
}

static void write_done(uv_write_t *req, int status) {
    g_free(req->data);
    g_free(req);
}

static void stream_write_copy(uv_stream_t *s, const void *data, size_t len) {
    uv_write_t *req = g_new0(uv_write_t, 1);
    req->data = g_memdup2(data, len);
    uv_buf_t buf = uv_buf_init(req->data, len);
    if (uv_write(req, s, &buf, 1, write_done) < 0) {
        g_free(req->data);
        g_free(req);
    }
}

/* send everything OpenSSL produced to the peer */
static void conn_flush(tls_conn_t *c) {
    char buf[16384];
    int n;
    while ((n = BIO_read(c->wbio, buf, sizeof(buf))) > 0) {
        stream_write_copy((uv_stream_t *)&c->tcp, buf, n);
    }
}

static void alloc_cb(uv_handle_t *h, size_t suggested, uv_buf_t *buf) {
    buf->base = g_malloc(suggested);
    buf->len = suggested;
}

/* plaintext from the user -> TLS -> peer */
static void inner_read_cb(uv_stream_t *s, ssize_t nread, const uv_buf_t *buf) {
    tls_conn_t *c = s->data;
    if (nread < 0) {
        g_free(buf->base);
        conn_close(c); /* user closed its end */
        return;
    }
    if (nread > 0 && !c->closing) {
        if (SSL_write(c->ssl, buf->base, nread) <= 0) {
            g_free(buf->base);
            conn_close(c);
            return;
        }
        conn_flush(c);
    }
    g_free(buf->base);
}

static uv_stream_t *conn_open_plain(tls_conn_t *c) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, sv) < 0) {
        return NULL;
    }

    uv_pipe_init(c->loop, &c->inner, 0);
    uv_pipe_open(&c->inner, sv[0]);
    c->inner.data = c;
    c->inner_open = TRUE;
    c->refs++;
    uv_read_start((uv_stream_t *)&c->inner, alloc_cb, inner_read_cb);

    uv_pipe_t *plain = raft_malloc(sizeof(uv_pipe_t));
    uv_pipe_init(c->loop, plain, 0);
    uv_pipe_open(plain, sv[1]);

    c->opened = TRUE;
    uv_timer_stop(&c->timer);
    return (uv_stream_t *)plain;
}

/* decrypted data from the peer */
static void conn_plaintext(tls_conn_t *c, const char *data, size_t len) {
    if (c->opened) {
        stream_write_copy((uv_stream_t *)&c->inner, data, len);
        return;
    }

    /* server: collect and check the preamble first */
    g_byte_array_append(c->pre, (const guint8 *)data, len);
    if (c->pre->len < sizeof(wire_preamble_t)) {
        return;
    }

    wire_preamble_t w;
    memcpy(&w, c->pre->data, sizeof(w));
    if (w.magic != PREAMBLE_MAGIC) {
        cfs_message("tls: bad preamble - closing connection");
        conn_close(c);
        return;
    }

    rsm_preamble_t pre = {.kind = w.kind, .id = w.id};
    memcpy(pre.address, w.address, sizeof(pre.address));
    pre.address[sizeof(pre.address) - 1] = 0;

    uv_stream_t *plain = conn_open_plain(c);
    if (!plain) {
        conn_close(c);
        return;
    }
    if (c->pre->len > sizeof(w)) {
        stream_write_copy(
            (uv_stream_t *)&c->inner, c->pre->data + sizeof(w), c->pre->len - sizeof(w)
        );
    }
    c->acb(c->arg, &pre, plain);
}

static void conn_process(tls_conn_t *c) {
    if (!c->established) {
        int r = SSL_do_handshake(c->ssl);
        conn_flush(c);
        if (r != 1) {
            int e = SSL_get_error(c->ssl, r);
            if (e != SSL_ERROR_WANT_READ && e != SSL_ERROR_WANT_WRITE) {
                unsigned long ossl = ERR_get_error();
                cfs_message(
                    "tls: handshake failed (%s)",
                    ossl ? ERR_reason_error_string(ossl) : "connection closed"
                );
                ERR_clear_error();
                conn_close(c);
            }
            return;
        }
        c->established = TRUE;

        if (!c->server) {
            SSL_write(c->ssl, &c->wpre, sizeof(c->wpre));
            conn_flush(c);
            uv_stream_t *plain = conn_open_plain(c);
            c->notified = TRUE;
            if (!plain) {
                c->ccb(c->arg, NULL, -EIO);
                conn_close(c);
                return;
            }
            c->ccb(c->arg, plain, 0);
        }
    }

    char buf[16384];
    for (;;) {
        int n = SSL_read(c->ssl, buf, sizeof(buf));
        if (n > 0) {
            conn_plaintext(c, buf, n);
            if (c->closing) {
                return;
            }
            continue;
        }
        int e = SSL_get_error(c->ssl, n);
        if (e != SSL_ERROR_WANT_READ) {
            ERR_clear_error();
            conn_close(c);
            return;
        }
        break;
    }
    conn_flush(c);
}

static void tcp_read_cb(uv_stream_t *s, ssize_t nread, const uv_buf_t *buf) {
    tls_conn_t *c = s->data;
    if (nread < 0) {
        g_free(buf->base);
        conn_close(c);
        return;
    }
    if (nread > 0 && !c->closing) {
        BIO_write(c->rbio, buf->base, nread);
        conn_process(c);
    }
    g_free(buf->base);
}

static void handshake_timeout_cb(uv_timer_t *t) {
    tls_conn_t *c = t->data;
    cfs_message("tls: handshake timeout");
    conn_close(c);
}

static tls_conn_t *conn_new(uv_loop_t *loop, gboolean server) {
    tls_conn_t *c = g_new0(tls_conn_t, 1);
    c->loop = loop;
    c->server = server;
    c->refs = 2; /* tcp + timer */
    uv_tcp_init(loop, &c->tcp);
    uv_tcp_nodelay(&c->tcp, 1);
    c->tcp.data = c;
    uv_timer_init(loop, &c->timer);
    c->timer.data = c;
    uv_timer_start(&c->timer, handshake_timeout_cb, HANDSHAKE_TIMEOUT_MS, 0);

    c->ssl = SSL_new(server ? server_ctx : client_ctx);
    c->rbio = BIO_new(BIO_s_mem());
    c->wbio = BIO_new(BIO_s_mem());
    SSL_set_bio(c->ssl, c->rbio, c->wbio);
    if (server) {
        SSL_set_accept_state(c->ssl);
        c->pre = g_byte_array_new();
    } else {
        SSL_set_connect_state(c->ssl);
    }
    return c;
}

static void tcp_connect_cb(uv_connect_t *req, int status) {
    tls_conn_t *c = req->data;
    if (status < 0) {
        conn_close(c);
        return;
    }
    uv_read_start((uv_stream_t *)&c->tcp, alloc_cb, tcp_read_cb);
    conn_process(c); /* sends ClientHello */
}

int rsm_tls_connect(
    uv_loop_t *loop,
    const char *ip,
    int port,
    const rsm_preamble_t *pre,
    rsm_tls_connect_cb cb,
    void *arg
) {
    struct sockaddr_in addr;
    int rc = uv_ip4_addr(ip, port, &addr);
    if (rc < 0) {
        return rc;
    }

    tls_conn_t *c = conn_new(loop, FALSE);
    c->ccb = cb;
    c->arg = arg;
    c->wpre.magic = PREAMBLE_MAGIC;
    c->wpre.kind = pre->kind;
    c->wpre.id = pre->id;
    g_strlcpy(c->wpre.address, pre->address, sizeof(c->wpre.address));

    c->creq.data = c;
    rc = uv_tcp_connect(&c->creq, &c->tcp, (struct sockaddr *)&addr, tcp_connect_cb);
    if (rc < 0) {
        c->notified = TRUE; /* caller sees the error code */
        conn_close(c);
        return rc;
    }
    return 0;
}

typedef struct {
    uv_tcp_t tcp;
    rsm_tls_accept_cb cb;
    void *arg;
} tls_listener_t;

static void listen_cb(uv_stream_t *server, int status) {
    tls_listener_t *l = server->data;
    if (status < 0) {
        return;
    }
    tls_conn_t *c = conn_new(server->loop, TRUE);
    c->acb = l->cb;
    c->arg = l->arg;
    if (uv_accept(server, (uv_stream_t *)&c->tcp) < 0) {
        conn_close(c);
        return;
    }
    uv_read_start((uv_stream_t *)&c->tcp, alloc_cb, tcp_read_cb);
}

int rsm_tls_listen(uv_loop_t *loop, const char *ip, int port, rsm_tls_accept_cb cb, void *arg) {
    struct sockaddr_in addr;
    int rc = uv_ip4_addr(ip, port, &addr);
    if (rc < 0) {
        return rc;
    }

    tls_listener_t *l = g_new0(tls_listener_t, 1);
    l->cb = cb;
    l->arg = arg;
    uv_tcp_init(loop, &l->tcp);
    l->tcp.data = l;
    if ((rc = uv_tcp_bind(&l->tcp, (struct sockaddr *)&addr, 0)) < 0 ||
        (rc = uv_listen((uv_stream_t *)&l->tcp, 128, listen_cb)) < 0) {
        return rc;
    }
    return 0;
}

/* ---- raft transport ---- */

typedef struct {
    uv_loop_t *loop;
    raft_id id;
    char address[64];
    raft_uv_accept_cb accept_cb;
    gboolean closed;
} tls_transport_t;

typedef struct {
    struct raft_uv_transport *t;
    struct raft_uv_connect *req;
} transport_connect_t;

static int transport_init(struct raft_uv_transport *t, raft_id id, const char *address) {
    tls_transport_t *tt = t->impl;
    tt->id = id;
    g_strlcpy(tt->address, address, sizeof(tt->address));
    return 0;
}

static int transport_listen(struct raft_uv_transport *t, raft_uv_accept_cb cb) {
    tls_transport_t *tt = t->impl;
    tt->accept_cb = cb;
    return 0;
}

static void plain_close_cb(uv_handle_t *h) { raft_free(h); }

static void transport_connect_done(void *arg, uv_stream_t *plain, int status) {
    transport_connect_t *tc = arg;
    tls_transport_t *tt = tc->t->impl;
    struct raft_uv_connect *req = tc->req;
    g_free(tc);

    if (status != 0) {
        req->cb(req, NULL, RAFT_NOCONNECTION);
    } else if (tt->closed) {
        uv_close((uv_handle_t *)plain, plain_close_cb);
        req->cb(req, NULL, RAFT_CANCELED);
    } else {
        req->cb(req, plain, 0);
    }
}

static int transport_connect(
    struct raft_uv_transport *t,
    struct raft_uv_connect *req,
    raft_id id,
    const char *address,
    raft_uv_connect_cb cb
) {
    tls_transport_t *tt = t->impl;
    char ip[64];

    const char *colon = strrchr(address, ':');
    if (!colon || colon - address >= (int)sizeof(ip)) {
        return RAFT_NOCONNECTION;
    }
    memcpy(ip, address, colon - address);
    ip[colon - address] = 0;

    rsm_preamble_t pre = {.kind = RSM_KIND_RAFT, .id = tt->id};
    g_strlcpy(pre.address, tt->address, sizeof(pre.address));

    req->cb = cb;
    transport_connect_t *tc = g_new0(transport_connect_t, 1);
    tc->t = t;
    tc->req = req;
    if (rsm_tls_connect(tt->loop, ip, atoi(colon + 1), &pre, transport_connect_done, tc) != 0) {
        g_free(tc);
        return RAFT_NOCONNECTION;
    }
    return 0;
}

static void transport_close(struct raft_uv_transport *t, raft_uv_transport_close_cb cb) {
    tls_transport_t *tt = t->impl;
    tt->closed = TRUE;
    if (cb) {
        cb(t);
    }
}

int rsm_tls_transport_init(struct raft_uv_transport *t, uv_loop_t *loop) {
    tls_transport_t *tt = g_new0(tls_transport_t, 1);
    tt->loop = loop;
    t->version = 1;
    t->impl = tt;
    t->init = transport_init;
    t->listen = transport_listen;
    t->connect = transport_connect;
    t->close = transport_close;
    return 0;
}

void rsm_tls_transport_accept(
    struct raft_uv_transport *t, const rsm_preamble_t *pre, uv_stream_t *plain
) {
    tls_transport_t *tt = t->impl;
    if (!tt->accept_cb || tt->closed) {
        uv_close((uv_handle_t *)plain, plain_close_cb);
        return;
    }
    tt->accept_cb(t, pre->id, pre->address, plain);
}
