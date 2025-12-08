#ifndef COMMON_H
#define COMMON_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

/* --------------------------------------------------------------------------
 * [상수 정의] SMB 프로토콜 명령어 코드
 * -------------------------------------------------------------------------- */

/* [FIX] 누락되었던 SMB1 명령어 정의 추가 */
enum smb1_commands {
    SMB1_COM_WRITE       = 0x0B,
    SMB1_COM_WRITE_ANDX  = 0x2F
};

/* SMB2/3 명령어 */
enum smb2_commands {
    SMB2_CREATE = 0x0005,
    SMB2_READ   = 0x0008,
    SMB2_WRITE  = 0x0009
};

static const uint32_t SMB2_FLAGS_SERVER_TO_REDIR = 0x00000001;

/* --------------------------------------------------------------------------
 * [구조체 정의] 데이터 모델
 * -------------------------------------------------------------------------- */

/* TCP 연결 식별 키 (IP/Port 쌍) */
typedef struct conn_key {
    uint32_t cli_ip; uint16_t cli_port;
    uint32_t srv_ip; uint16_t srv_port;
} conn_key_t;

/* TCP 스트림 상태 (시퀀스 넘버 추적용) */
typedef struct tcp_stream {
    uint32_t next_seq;
    int has_next_seq;
} tcp_stream_t;

/* SMB2 READ 요청 대기열 */
typedef struct pending_read {
    uint64_t msg_id;
    uint8_t file_id[16];
    uint64_t offset;
    uint32_t length;
    struct pending_read *next;
} pending_read_t;

/* SMB2 CREATE 요청 대기열 (요청 시 파일명을 임시 저장) */
typedef struct pending_create {
    uint64_t msg_id;
    char *name;
    struct pending_create *next;
} pending_create_t;

/* FileId <-> Filename 매핑 테이블 */
typedef struct file_name_map {
    uint8_t file_id[16];
    char *name;
    struct file_name_map *next;
} file_name_map_t;

/* SMB 데이터 버퍼 */
typedef struct smb_stream {
    uint8_t *buf;
    size_t buf_len;
    size_t buf_cap;
    pending_read_t *pending;
} smb_stream_t;

/* 연결 컨텍스트 (메인 구조체) */
typedef struct connection {
    conn_key_t key;
    tcp_stream_t tcp[2];
    smb_stream_t smb[2];
    pending_create_t *pending_creates; /* CREATE 요청 대기열 */
    file_name_map_t *file_names;       /* 복구된 파일명 매핑 리스트 */
    struct connection *next;
} connection_t;

/* --------------------------------------------------------------------------
 * [함수 프로토타입 & 전역 변수]
 * -------------------------------------------------------------------------- */
extern char *output_dir; // main.c에 정의됨

/* tcp_stream.c */
connection_t *get_connection(const conn_key_t *key);
void feed_tcp_payload(connection_t *conn, int dir, uint32_t seq, const uint8_t *payload, size_t len);
void smb_feed_bytes(connection_t *conn, int dir, const uint8_t *data, size_t len);

/* file_utils.c */
char *utf16le_to_utf8(const uint8_t *data, size_t byte_len);
void sanitize_path(const char *in, char *out, size_t out_size);
void remember_file_name(connection_t *conn, const uint8_t *file_id, const char *orig_name);
void write_file_chunk(connection_t *conn, const uint8_t *file_id, uint64_t offset, const uint8_t *data, size_t len);
void close_all_files();

/* smb_parser.c */
void parse_smb2_message(connection_t *conn, int dir, const uint8_t *msg, size_t len);
void parse_smb1_message(connection_t *conn, int dir, const uint8_t *msg, size_t len);

#endif
