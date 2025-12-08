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

enum smb1_commands {
    SMB1_COM_WRITE       = 0x0B,
    SMB1_COM_WRITE_ANDX  = 0x2F
};

enum smb2_commands {
    SMB2_CREATE = 0x0005,
    SMB2_READ   = 0x0008,
    SMB2_WRITE  = 0x0009
};

static const uint32_t SMB2_FLAGS_SERVER_TO_REDIR = 0x00000001;

typedef struct conn_key {
    uint32_t cli_ip; uint16_t cli_port;
    uint32_t srv_ip; uint16_t srv_port;
} conn_key_t;

typedef struct tcp_stream {
    uint32_t next_seq;
    int has_next_seq;
} tcp_stream_t;

typedef struct pending_read {
    uint64_t msg_id;
    uint8_t file_id[16];
    uint64_t offset;
    uint32_t length;
    struct pending_read *next;
} pending_read_t;

typedef struct pending_create {
    uint64_t msg_id;
    char *name;
    struct pending_create *next;
} pending_create_t;

typedef struct file_name_map {
    uint8_t file_id[16];
    char *name;
    struct file_name_map *next;
} file_name_map_t;

typedef struct smb_stream {
    uint8_t *buf;
    size_t buf_len;
    size_t buf_cap;
    pending_read_t *pending;
} smb_stream_t;

typedef struct connection {
    conn_key_t key;
    tcp_stream_t tcp[2];
    smb_stream_t smb[2];
    pending_create_t *pending_creates;
    file_name_map_t *file_names;
    struct connection *next;
} connection_t;

extern char *output_dir;

connection_t *get_connection(const conn_key_t *key);
void feed_tcp_payload(connection_t *conn, int dir, uint32_t seq, const uint8_t *payload, size_t len);
void smb_feed_bytes(connection_t *conn, int dir, const uint8_t *data, size_t len);

char *utf16le_to_utf8(const uint8_t *data, size_t byte_len);
void sanitize_path(const char *in, char *out, size_t out_size);
void remember_file_name(connection_t *conn, const uint8_t *file_id, const char *orig_name);
void write_file_chunk(connection_t *conn, const uint8_t *file_id, uint64_t offset, const uint8_t *data, size_t len);
void close_all_files();

void parse_smb2_message(connection_t *conn, int dir, const uint8_t *msg, size_t len);
void parse_smb1_message(connection_t *conn, int dir, const uint8_t *msg, size_t len);

#endif