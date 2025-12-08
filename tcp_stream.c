#include "smb_reassemble.h"

static connection_t *connections = NULL; // 전역 연결 리스트

/* 두 키(IP/Port)가 같은지 비교하는 함수 */
static int conn_key_equal(const conn_key_t *a, const conn_key_t *b) {
    return a->cli_ip == b->cli_ip && a->cli_port == b->cli_port &&
           a->srv_ip == b->srv_ip && a->srv_port == b->srv_port;
}

/* 키를 기반으로 연결 구조체를 찾거나 생성하는 함수 */
connection_t *get_connection(const conn_key_t *key) {
    connection_t *c;
    // 기존 리스트 순회
    for (c = connections; c; c = c->next) {
        if (conn_key_equal(&c->key, key)) return c;
    }
    // 없으면 생성
    c = (connection_t *)calloc(1, sizeof(connection_t));
    if (!c) exit(EXIT_FAILURE);
    c->key = *key;
    c->next = connections;
    connections = c;
    return c;
}

/* 버퍼 크기를 늘려주는 함수 (메모리 관리) */
static void ensure_capacity(smb_stream_t *s, size_t needed) {
    if (s->buf_cap >= needed) return;
    size_t new_cap = s->buf_cap ? s->buf_cap * 2 : 1024;
    while (new_cap < needed) new_cap *= 2;
    uint8_t *new_buf = (uint8_t *)realloc(s->buf, new_cap);
    if (!new_buf) exit(EXIT_FAILURE);
    s->buf = new_buf;
    s->buf_cap = new_cap;
}

/*
 * smb_feed_bytes
 * 역할: 순서대로 맞춰진 TCP 데이터를 받아서, NBSS(NetBIOS) 단위로 자른 뒤 SMB 파서 호출
 * 변수 설명:
 * - s: 현재 연결/방향의 SMB 버퍼
 * - nbss_len: NetBIOS 헤더에 적힌 메시지 길이
 */
void smb_feed_bytes(connection_t *conn, int dir, const uint8_t *data, size_t len) {
    smb_stream_t *s = &conn->smb[dir];
    ensure_capacity(s, s->buf_len + len);
    memcpy(s->buf + s->buf_len, data, len);
    s->buf_len += len;
    
    size_t pos = 0; // 버퍼 내 처리 위치
    while (s->buf_len - pos >= 4) {
        // NBSS 헤더 파싱 (Big Endian)
        uint32_t nbss_len = (s->buf[pos + 1] << 16) | (s->buf[pos + 2] << 8) | s->buf[pos + 3];
        size_t total_len = 4 + nbss_len;
        
        if (s->buf_len - pos < total_len) break; // 데이터가 덜 왔으면 대기

        const uint8_t *msg = s->buf + pos + 4; // 실제 SMB 메시지 시작점
        if (nbss_len >= 4) {
            if (msg[0] == 0xFE) parse_smb2_message(conn, dir, msg, nbss_len);
            else if (msg[0] == 0xFF) parse_smb1_message(conn, dir, msg, nbss_len);
        }
        pos += total_len;
    }
    
    // 처리한 데이터 제거 (메모리 앞당기기)
    if (pos > 0) {
        memmove(s->buf, s->buf + pos, s->buf_len - pos);
        s->buf_len -= pos;
    }
}

/* TCP 페이로드를 받아서 순서 확인 후 전달 */
void feed_tcp_payload(connection_t *conn, int dir, uint32_t seq, const uint8_t *payload, size_t len) {
    tcp_stream_t *ts = &conn->tcp[dir];
    if (len == 0) return;
    
    // 간단한 재조합 로직 (Out-of-order 패킷은 드롭하여 복잡도 낮춤)
    if (!ts->has_next_seq) {
        ts->next_seq = seq + len;
        ts->has_next_seq = 1;
        smb_feed_bytes(conn, dir, payload, len);
    } else if (seq == ts->next_seq) {
        ts->next_seq += len;
        smb_feed_bytes(conn, dir, payload, len);
    }
}
