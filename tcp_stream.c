#include "smb_reassemble.h"

static connection_t *connections = NULL;

static int conn_key_equal(const conn_key_t *a, const conn_key_t *b) {
    return a->cli_ip == b->cli_ip && a->cli_port == b->cli_port &&
           a->srv_ip == b->srv_ip && a->srv_port == b->srv_port;
}

connection_t *get_connection(const conn_key_t *key) {
    connection_t *c;
    for (c = connections; c; c = c->next) {
        if (conn_key_equal(&c->key, key)) return c;
    }
    c = (connection_t *)calloc(1, sizeof(connection_t));
    if (!c) exit(EXIT_FAILURE);
    c->key = *key;
    c->next = connections;
    connections = c;
    return c;
}

static void ensure_capacity(smb_stream_t *s, size_t needed) {
    if (s->buf_cap >= needed) return;
    size_t new_cap = s->buf_cap ? s->buf_cap * 2 : 1024;
    while (new_cap < needed) new_cap *= 2;
    uint8_t *new_buf = (uint8_t *)realloc(s->buf, new_cap);
    if (!new_buf) exit(EXIT_FAILURE);
    s->buf = new_buf;
    s->buf_cap = new_cap;
}

void smb_feed_bytes(connection_t *conn, int dir, const uint8_t *data, size_t len) {
    smb_stream_t *s = &conn->smb[dir];
    ensure_capacity(s, s->buf_len + len);
    memcpy(s->buf + s->buf_len, data, len);
    s->buf_len += len;
    
    size_t pos = 0;
    while (s->buf_len - pos >= 4) {
        uint32_t nbss_len = (s->buf[pos + 1] << 16) | (s->buf[pos + 2] << 8) | s->buf[pos + 3];
        size_t total_len = 4 + nbss_len;
        
        if (s->buf_len - pos < total_len) break;

        const uint8_t *msg = s->buf + pos + 4;
        if (nbss_len >= 4) {
            if (msg[0] == 0xFE) parse_smb2_message(conn, dir, msg, nbss_len);
            else if (msg[0] == 0xFF) parse_smb1_message(conn, dir, msg, nbss_len);
        }
        pos += total_len;
    }
    
    if (pos > 0) {
        memmove(s->buf, s->buf + pos, s->buf_len - pos);
        s->buf_len -= pos;
    }
}

void feed_tcp_payload(connection_t *conn, int dir, uint32_t seq, const uint8_t *payload, size_t len) {
    tcp_stream_t *ts = &conn->tcp[dir];
    if (len == 0) return;
    
    if (!ts->has_next_seq) {
        ts->next_seq = seq + len;
        ts->has_next_seq = 1;
        smb_feed_bytes(conn, dir, payload, len);
    } else if (seq == ts->next_seq) {
        ts->next_seq += len;
        smb_feed_bytes(conn, dir, payload, len);
    }
}