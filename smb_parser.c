#include "smb_reassemble.h"

static void record_pending_create(connection_t *conn, uint64_t msg_id, const uint8_t *body, size_t len) {
    if (len < 52) return;
    
    uint16_t name_offset = body[44] | (body[45] << 8);
    uint16_t name_length = body[46] | (body[47] << 8);
    
    if (name_length == 0 || name_offset < 64) return;
    
    size_t rel = (size_t)name_offset - 64;
    if (rel + name_length > len) return;
    
    const uint8_t *name_utf16 = body + rel;
    char *utf8 = utf16le_to_utf8(name_utf16, name_length);
    if (!utf8) return;
    
    pending_create_t *pc = (pending_create_t *)calloc(1, sizeof(pending_create_t));
    pc->msg_id = msg_id;
    pc->name = utf8;
    pc->next = conn->pending_creates;
    conn->pending_creates = pc;
}

static void handle_create_response(connection_t *conn, uint64_t msg_id, const uint8_t *body, size_t len) {
    pending_create_t **prev = &conn->pending_creates;
    pending_create_t *pc = conn->pending_creates;
    
    while (pc) {
        if (pc->msg_id == msg_id) break;
        prev = &pc->next;
        pc = pc->next;
    }
    
    if (!pc) return;
    
    if (len >= 80) {
        const uint8_t *file_id = body + 64;
        remember_file_name(conn, file_id, pc->name);
    }
    
    *prev = pc->next;
    free(pc->name);
    free(pc);
}

static void record_pending_read(connection_t *conn, uint64_t msg_id, const uint8_t *body, size_t len) {
    if (len < 48) return;
    uint32_t length = body[4] | (body[5] << 8) | (body[6] << 16) | (body[7] << 24);
    uint64_t offset = 0;
    for (int i = 0; i < 8; i++) offset |= ((uint64_t)body[8 + i]) << (8 * i);
    const uint8_t *file_id = body + 24;
    
    pending_read_t *pr = (pending_read_t *)calloc(1, sizeof(pending_read_t));
    pr->msg_id = msg_id;
    memcpy(pr->file_id, file_id, 16);
    pr->offset = offset;
    pr->length = length;
    pr->next = conn->smb[0].pending;
    conn->smb[0].pending = pr;
}

static void handle_read_response(connection_t *conn, uint64_t msg_id, const uint8_t *body, size_t len) {
    if (len < 16) return;
    uint16_t data_offset = body[2] | (body[3] << 8);
    uint32_t data_length = body[4] | (body[5] << 8) | (body[6] << 16) | (body[7] << 24);
    
    if (data_offset < 64) return;
    size_t data_start = (size_t)data_offset - 64;
    
    pending_read_t **prev = &conn->smb[0].pending;
    pending_read_t *pr = conn->smb[0].pending;
    while (pr) {
        if (pr->msg_id == msg_id) break;
        prev = &pr->next;
        pr = pr->next;
    }
    if (!pr) return;
    
    *prev = pr->next;
    write_file_chunk(conn, pr->file_id, pr->offset, body + data_start, data_length);
    free(pr);
}

void parse_smb2_message(connection_t *conn, int dir, const uint8_t *msg, size_t len) {
    size_t offset = 0;
    while (offset < len) {
        if (len - offset < 64) break;
        const uint8_t *hdr = msg + offset;
        
        if (!(hdr[0] == 0xFE && hdr[1] == 'S' && hdr[2] == 'M' && hdr[3] == 'B')) break;
        
        uint16_t command = hdr[12] | (hdr[13] << 8);
        uint32_t flags = hdr[16] | (hdr[17] << 8) | (hdr[18] << 16) | (hdr[19] << 24);
        uint32_t next_cmd = hdr[20] | (hdr[21] << 8) | (hdr[22] << 16) | (hdr[23] << 24);
        
        uint64_t msg_id = 0;
        for (int i = 0; i < 8; i++) msg_id |= ((uint64_t)hdr[24 + i]) << (8 * i);
        
        int is_response = (flags & SMB2_FLAGS_SERVER_TO_REDIR) != 0;
        size_t body_len = (next_cmd == 0) ? ((len > offset + 64) ? len - offset - 64 : 0) : (next_cmd - 64);
        const uint8_t *body = hdr + 64;

        if (!is_response) {
            if (command == SMB2_READ && dir == 0) {
                record_pending_read(conn, msg_id, body, body_len);
            } else if (command == SMB2_WRITE && dir == 0) {
                if (body_len >= 32) {
                    uint16_t data_offset = body[2] | (body[3] << 8);
                    uint32_t data_length = body[4] | (body[5] << 8) | (body[6] << 16) | (body[7] << 24);
                    uint64_t file_offset = 0;
                    for (int i = 0; i < 8; i++) file_offset |= ((uint64_t)body[8 + i]) << (8 * i);
                    const uint8_t *file_id = body + 24;
                    
                    if (data_offset >= 64) {
                        size_t data_start = (size_t)data_offset - 64;
                        if (body_len >= data_start + data_length) {
                            write_file_chunk(conn, file_id, file_offset, body + data_start, data_length);
                        }
                    }
                }
            } else if (command == SMB2_CREATE && dir == 0) {
                record_pending_create(conn, msg_id, body, body_len);
            }
        } else {
            if (command == SMB2_READ && dir == 1) {
                handle_read_response(conn, msg_id, body, body_len);
            } else if (command == SMB2_CREATE && dir == 1) {
                handle_create_response(conn, msg_id, body, body_len);
            }
        }
        
        if (next_cmd == 0) break;
        offset += next_cmd;
    }
}

static void create_file_id_smb1(const connection_t *conn, uint16_t fid, uint8_t file_id[16]) {
    memset(file_id, 0, 16);
    file_id[0] = (uint8_t)(fid & 0xFF);
    file_id[1] = (uint8_t)((fid >> 8) & 0xFF);
    memcpy(&file_id[2], &conn->key.cli_ip, 4);
    memcpy(&file_id[6], &conn->key.cli_port, 2);
    memcpy(&file_id[8], &conn->key.srv_ip, 4);
    memcpy(&file_id[12], &conn->key.srv_port, 2);
}

void parse_smb1_message(connection_t *conn, int dir, const uint8_t *msg, size_t len) {
    if (len < 32) return;
    if (!(msg[0] == 0xFF && msg[1] == 'S' && msg[2] == 'M' && msg[3] == 'B')) return;
    uint8_t command = msg[4];
    uint8_t word_count = msg[32];
    const uint8_t *params = msg + 33;
    
    if (command == SMB1_COM_WRITE_ANDX) {
        if (word_count < 12) return;
        uint16_t fid = params[6] | (params[7] << 8);
        uint16_t data_length = params[16] | (params[17] << 8);
        uint16_t data_offset = params[18] | (params[19] << 8);
        
        uint8_t file_id[16];
        create_file_id_smb1(conn, fid, file_id);
        write_file_chunk(conn, file_id, 0, msg + data_offset, data_length);
    } else if (command == SMB1_COM_WRITE) {
        uint16_t fid = params[0] | (params[1] << 8);
        uint16_t count = params[2] | (params[3] << 8);
        uint8_t file_id[16];
        create_file_id_smb1(conn, fid, file_id);
        write_file_chunk(conn, file_id, 0, params + word_count * 2 + 2, count);
    }
}