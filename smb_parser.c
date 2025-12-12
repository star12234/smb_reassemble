#include "smb_reassemble.h"

 //* - READ/WRITE Request의 FileID Offset을 16으로 강제 고정.


/* [DEBUG] Hex 값을 보기 좋게 출력하는 함수
static void print_hex_id(const char *label, const uint8_t *id) {
    printf("%s: ", label);
    for (int i = 0; i < 16; i++) printf("%02x", id[i]);
    printf("\n");
}
*/
/* READ 요청 기록 */
static void record_pending_read(connection_t *conn, uint64_t msg_id, const uint8_t *body, size_t len) {
    if (len < 48) return;

    const uint8_t *file_id = body + 16; 
    
    uint32_t length = body[4] | (body[5] << 8) | (body[6] << 16) | (body[7] << 24);
    uint64_t offset = 0;
    for (int i = 0; i < 8; i++) offset |= ((uint64_t)body[8 + i]) << (8 * i);
    
    pending_read_t *pr = (pending_read_t *)calloc(1, sizeof(pending_read_t));
    if (!pr) return;
    pr->msg_id = msg_id;
    memcpy(pr->file_id, file_id, 16);
    pr->offset = offset;
    pr->length = length;
    pr->next = conn->smb[0].pending;
    conn->smb[0].pending = pr;
}

/* READ 응답 처리 */
static void handle_read_response(connection_t *conn, uint64_t msg_id, const uint8_t *body, size_t len) {
    if (len < 16) return;
    uint16_t data_offset = body[2] | (body[3] << 8);
    uint32_t data_length = body[4] | (body[5] << 8) | (body[6] << 16) | (body[7] << 24);
    
    if (data_offset < 64) return;
    size_t data_start = (size_t)data_offset - 64;
    if (len < data_start + data_length) return;
    
    pending_read_t **prev = &conn->smb[0].pending;
    pending_read_t *pr = conn->smb[0].pending;
    while (pr) {
        if (pr->msg_id == msg_id) break;
        prev = &pr->next;
        pr = pr->next;
    }
    if (!pr) return;
    
    *prev = pr->next;
    
    // [DEBUG] 어떤 ID로 쓰기를 시도하는지 출력
    // print_hex_id("[DEBUG] READ Resp processing ID", pr->file_id);
    
    write_file_chunk(conn, pr->file_id, pr->offset, body + data_start, data_length);
    free(pr);
}

/* [CREATE Request] Offset 44/48 자동 감지 */
static void record_pending_create(connection_t *conn, uint64_t msg_id, const uint8_t *body, size_t len) {
    if (len < 60) return;

    // 1. 오프셋 44 (Standard/Windows/smbclient)
    uint16_t name_offset_44 = body[44] | (body[45] << 8);
    uint16_t name_len_44 = body[46] | (body[47] << 8);

    // 2. 오프셋 48 (Linux VFS)
    uint16_t name_offset_48 = body[48] | (body[49] << 8);
    uint16_t name_len_48 = body[50] | (body[51] << 8);

    uint16_t final_offset = 0;
    uint16_t final_len = 0;

    if (name_offset_44 >= 64 && name_offset_44 < 200 && name_len_44 > 0 && name_len_44 < 512) {
        final_offset = name_offset_44;
        final_len = name_len_44;
    } 
    else if (name_offset_48 >= 64 && name_offset_48 < 200 && name_len_48 > 0 && name_len_48 < 512) {
        final_offset = name_offset_48;
        final_len = name_len_48;
    } else {
        return;
    }
    
    size_t rel = (size_t)final_offset - 64;
    if (rel + final_len > len) return;
    
    const uint8_t *name_utf16 = body + rel;
    char *utf8 = utf16le_to_utf8(name_utf16, final_len);
    if (!utf8) return;
    
    pending_create_t *pc = (pending_create_t *)calloc(1, sizeof(pending_create_t));
    pc->msg_id = msg_id;
    pc->name = utf8;
    pc->next = conn->pending_creates;
    conn->pending_creates = pc;
}

/* [CREATE Response] ID 매핑 저장 */
static void handle_create_response(connection_t *conn, uint64_t msg_id, const uint8_t *body, size_t len) {
    pending_create_t **prev = &conn->pending_creates;
    pending_create_t *pc = conn->pending_creates;
    while (pc) {
        if (pc->msg_id == msg_id) break;
        prev = &pc->next;
        pc = pc->next;
    }
    if (!pc) return;
    if (len < 80) return;

    // Offset 64 is standard for Create Response FileId
    const uint8_t *file_id = body + 64; 
    
    // [DEBUG] 매핑되는 ID 확인
    printf("[INFO] Mapped ID to Name: %s\n", pc->name);
    // print_hex_id("       -> ID", file_id);

    remember_file_name(conn, file_id, pc->name);
    
    *prev = pc->next;
    free(pc->name);
    free(pc);
}

/* 메인 파서 */
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
                    
                    // [핵심 수정] SMB2 WRITE Request의 FileID 위치는 16입니다!
                    const uint8_t *file_id = body + 16;
                    
                    if (data_offset >= 64) {
                        size_t data_start = (size_t)data_offset - 64;
                        if (body_len >= data_start + data_length) {
                            // [DEBUG] 쓰기 시도 ID 확인
                            // print_hex_id("[DEBUG] WRITE Req ID", file_id);
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

/* SMB1 (기존 유지) */
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
    size_t params_len = (size_t)word_count * 2;
    
    if (len < 33 + params_len + 2) return;
    uint16_t byte_count = params[params_len] | (params[params_len + 1] << 8);
    const uint8_t *data_base = params + params_len + 2;
    
    if (data_base + byte_count > msg + len) return;
    if (dir != 0) return;

    if (command == SMB1_COM_WRITE_ANDX) {
        if (word_count < 12) return;
        uint16_t fid = params[6] | (params[7] << 8);
        uint16_t data_length = params[16] | (params[17] << 8);
        uint16_t data_offset = params[18] | (params[19] << 8);
        if (data_length == 0 || data_offset >= len) return;
        
        uint8_t file_id[16];
        create_file_id_smb1(conn, fid, file_id);
        write_file_chunk(conn, file_id, 0, msg + data_offset, data_length);
    } else if (command == SMB1_COM_WRITE) {
        if (word_count < 5) return;
        uint16_t fid = params[0] | (params[1] << 8);
        uint16_t count = params[2] | (params[3] << 8);
        uint8_t file_id[16];
        create_file_id_smb1(conn, fid, file_id);
        write_file_chunk(conn, file_id, 0, data_base, count);
    }
}