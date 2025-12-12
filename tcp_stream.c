#include "smb_reassemble.h"

static connection_t *connections = NULL; // 전역 연결 리스트

/* [NEW] 재조합을 위한 패킷 조각 구조체 정의 
 * (common.h 에서는 전방 선언만 했으므로 여기서 구체적 정의 필요)
 */
typedef struct tcp_fragment {
    uint32_t seq;               // 패킷의 시작 시퀀스 번호
    size_t len;                 // 데이터 길이
    uint8_t *data;              // 데이터 본문
    struct tcp_fragment *next;  // 다음 조각 포인터
} tcp_fragment_t;

/* 두 키(IP/Port)가 같은지 비교 */
static int conn_key_equal(const conn_key_t *a, const conn_key_t *b) {
    return a->cli_ip == b->cli_ip && a->cli_port == b->cli_port &&
           a->srv_ip == b->srv_ip && a->srv_port == b->srv_port;
}

/* 연결 구조체 조회 또는 생성 */
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

/* 버퍼 용량 확보 */
static void ensure_capacity(smb_stream_t *s, size_t needed) {
    if (s->buf_cap >= needed) return;
    size_t new_cap = s->buf_cap ? s->buf_cap * 2 : 1024;
    while (new_cap < needed) new_cap *= 2;
    uint8_t *new_buf = (uint8_t *)realloc(s->buf, new_cap);
    if (!new_buf) exit(EXIT_FAILURE);
    s->buf = new_buf;
    s->buf_cap = new_cap;
}

/* SMB 프로토콜 처리 (NBSS 파싱) */
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

/* [NEW] 순서 어긋난 패킷 저장 (Linked List 정렬 삽입) */
static void store_fragment(tcp_stream_t *ts, uint32_t seq, const uint8_t *payload, size_t len) {
    if (seq < ts->next_seq) return; // 이미 지나간 패킷 무시

    tcp_fragment_t *frag = (tcp_fragment_t *)calloc(1, sizeof(tcp_fragment_t));
    frag->seq = seq;
    frag->len = len;
    frag->data = (uint8_t *)malloc(len);
    if (!frag->data) exit(EXIT_FAILURE);
    memcpy(frag->data, payload, len);

    tcp_fragment_t **prev = (tcp_fragment_t **)&ts->fragments;
    tcp_fragment_t *curr = (tcp_fragment_t *)ts->fragments;

    /* SEQ 순서에 맞춰서 중간에 끼워넣기 (Insertion Sort) */
    while (curr) {
        if (curr->seq == seq) {
            // 중복 데이터면 저장 안 함
            free(frag->data);
            free(frag);
            return;
        }
        if (curr->seq > seq) {
            break;
        }
        prev = (tcp_fragment_t **)&curr->next;
        curr = curr->next;
    }
    
    frag->next = curr;
    *prev = frag;
}

/* [NEW] 저장된 패킷 중 처리 가능한 것 확인 및 처리 */
static void process_buffered_fragments(connection_t *conn, int dir) {
    tcp_stream_t *ts = &conn->tcp[dir];
    tcp_fragment_t *frag = (tcp_fragment_t *)ts->fragments;

    // 대기열 맨 앞이 우리가 기다리는 next_seq와 일치하는지 반복 확인
    while (frag && frag->seq == ts->next_seq) {
        // 일치하면 SMB 파서로 넘김
        smb_feed_bytes(conn, dir, frag->data, frag->len);
        ts->next_seq += frag->len;

        // 리스트에서 제거 및 메모리 해제
        ts->fragments = (struct tcp_fragment *)frag->next;
        free(frag->data);
        free(frag);

        // 다음 노드로 갱신
        frag = (tcp_fragment_t *)ts->fragments;
    }
}

/* TCP 페이로드 처리 (재조합 로직 포함) */
void feed_tcp_payload(connection_t *conn, int dir, uint32_t seq, const uint8_t *payload, size_t len) {
    tcp_stream_t *ts = &conn->tcp[dir];
    if (len == 0) return;
    
    // 1. 스트림의 첫 패킷인 경우 (초기화)
    if (!ts->has_next_seq) {
        ts->next_seq = seq + len;
        ts->has_next_seq = 1;
        smb_feed_bytes(conn, dir, payload, len);
        return;
    } 
    
    // 2. 순서가 정확히 맞는 경우 (Fast Path)
    if (seq == ts->next_seq) {
        ts->next_seq += len;
        smb_feed_bytes(conn, dir, payload, len);
        
        // 이 패킷 덕분에 이어서 처리할 수 있는 대기 패킷이 있는지 확인
        process_buffered_fragments(conn, dir);
    } 
    // 3. 미래의 패킷이 먼저 온 경우 (Out-of-Order) -> 저장!
    else if (seq > ts->next_seq) {
        store_fragment(ts, seq, payload, len);
    }
    // 4. seq < next_seq (과거 패킷, 재전송 등) -> 무시
}