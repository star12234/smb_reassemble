#include "smb_reassemble.h"

/*
 * record_pending_create
 * 역할: SMB2 CREATE Request 패킷에서 '파일명'을 추출해 대기열에 넣음
 * 변수 설명:
 * - name_offset, name_length: 패킷 내에서 파일명 위치와 길이
 * - rel: SMB2 Body 시작점으로부터의 상대 위치
 * - pc: 대기열에 추가할 새로운 구조체
 */
static void record_pending_create(connection_t *conn, uint64_t msg_id, const uint8_t *body, size_t len) {
    if (len < 52) return;
    
    // 표준 SMB2 오프셋(44)에서 위치 정보 읽기
    uint16_t name_offset = body[44] | (body[45] << 8);
    uint16_t name_length = body[46] | (body[47] << 8);
    
    if (name_length == 0 || name_offset < 64) return;
    
    size_t rel = (size_t)name_offset - 64; // 헤더 길이(64)를 뺌
    if (rel + name_length > len) return;   // 버퍼 오버플로우 방지
    
    const uint8_t *name_utf16 = body + rel;
    char *utf8 = utf16le_to_utf8(name_utf16, name_length); // 변환
    if (!utf8) return;
    
    // 대기열 생성 및 저장
    pending_create_t *pc = (pending_create_t *)calloc(1, sizeof(pending_create_t));
    pc->msg_id = msg_id; // 나중에 응답과 매칭할 ID
    pc->name = utf8;
    pc->next = conn->pending_creates;
    conn->pending_creates = pc;
}

/*
 * handle_create_response
 * 역할: SMB2 CREATE Response 패킷에서 'FileId'를 추출해 파일명과 연결
 */
static void handle_create_response(connection_t *conn, uint64_t msg_id, const uint8_t *body, size_t len) {
    // 리스트 탐색을 위한 포인터들
    pending_create_t **prev = &conn->pending_creates;
    pending_create_t *pc = conn->pending_creates;
    
    // MsgId가 일치하는 요청 찾기
    while (pc) {
        if (pc->msg_id == msg_id) break;
        prev = &pc->next;
        pc = pc->next;
    }
    
    if (!pc) return; // 매칭 실패
    
    if (len >= 80) {
        // FileId는 응답 바디의 64번 위치에 있음
        const uint8_t *file_id = body + 64;
        // file_utils.c에 있는 함수 호출하여 매핑 등록
        remember_file_name(conn, file_id, pc->name);
    }
    
    // 처리 완료된 요청 제거
    *prev = pc->next;
    free(pc->name);
    free(pc);
}

/* READ 요청 정보 저장 (나중에 응답 오면 파일에 쓰려고) */
static void record_pending_read(connection_t *conn, uint64_t msg_id, const uint8_t *body, size_t len) {
    if (len < 48) return;
    // 읽을 길이와 위치(Offset) 파싱
    uint32_t length = body[4] | (body[5] << 8) | (body[6] << 16) | (body[7] << 24);
    uint64_t offset = 0;
    for (int i = 0; i < 8; i++) offset |= ((uint64_t)body[8 + i]) << (8 * i);
    const uint8_t *file_id = body + 24;
    
    // 대기열 추가
    pending_read_t *pr = (pending_read_t *)calloc(1, sizeof(pending_read_t));
    pr->msg_id = msg_id;
    memcpy(pr->file_id, file_id, 16);
    pr->offset = offset;
    pr->length = length;
    pr->next = conn->smb[0].pending;
    conn->smb[0].pending = pr;
}

/* READ 응답 처리 (데이터 파일에 쓰기) */
static void handle_read_response(connection_t *conn, uint64_t msg_id, const uint8_t *body, size_t len) {
    if (len < 16) return;
    uint16_t data_offset = body[2] | (body[3] << 8);
    uint32_t data_length = body[4] | (body[5] << 8) | (body[6] << 16) | (body[7] << 24);
    
    if (data_offset < 64) return;
    size_t data_start = (size_t)data_offset - 64;
    
    // 대기열에서 요청 찾기
    pending_read_t **prev = &conn->smb[0].pending;
    pending_read_t *pr = conn->smb[0].pending;
    while (pr) {
        if (pr->msg_id == msg_id) break;
        prev = &pr->next;
        pr = pr->next;
    }
    if (!pr) return;
    
    // 데이터 쓰기
    *prev = pr->next;
    write_file_chunk(conn, pr->file_id, pr->offset, body + data_start, data_length);
    free(pr);
}

/*
 * parse_smb2_message
 * 역할: SMB2 패킷 전체 구조를 분석하고 명령어에 따라 분기
 */
void parse_smb2_message(connection_t *conn, int dir, const uint8_t *msg, size_t len) {
    size_t offset = 0; // 현재 파싱 중인 패킷 내 위치
    while (offset < len) {
        if (len - offset < 64) break;
        const uint8_t *hdr = msg + offset;
        
        // 시그니처(Protocol ID) 확인: 0xFE 'S' 'M' 'B'
        if (!(hdr[0] == 0xFE && hdr[1] == 'S' && hdr[2] == 'M' && hdr[3] == 'B')) break;
        
        // Command Code 추출 (12~13바이트)
        uint16_t command = hdr[12] | (hdr[13] << 8);
        // Flags 추출 (응답 여부 확인용)
        uint32_t flags = hdr[16] | (hdr[17] << 8) | (hdr[18] << 16) | (hdr[19] << 24);
        // Next Command Offset (Compound Packet 처리용)
        uint32_t next_cmd = hdr[20] | (hdr[21] << 8) | (hdr[22] << 16) | (hdr[23] << 24);
        
        // Message ID 추출 (요청-응답 매칭용)
        uint64_t msg_id = 0;
        for (int i = 0; i < 8; i++) msg_id |= ((uint64_t)hdr[24 + i]) << (8 * i);
        
        int is_response = (flags & SMB2_FLAGS_SERVER_TO_REDIR) != 0;
        size_t body_len = (next_cmd == 0) ? ((len > offset + 64) ? len - offset - 64 : 0) : (next_cmd - 64);
        const uint8_t *body = hdr + 64; // 헤더(64) 뒤가 본문

        if (!is_response) { /* 클라이언트 -> 서버 (요청) */
            if (command == SMB2_READ && dir == 0) {
                record_pending_read(conn, msg_id, body, body_len);
            } else if (command == SMB2_WRITE && dir == 0) {
                // WRITE Request는 바로 데이터가 있으므로 즉시 처리
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
                // 파일명 복구를 위해 CREATE 요청 기록
                record_pending_create(conn, msg_id, body, body_len);
            }
        } else { /* 서버 -> 클라이언트 (응답) */
            if (command == SMB2_READ && dir == 1) {
                handle_read_response(conn, msg_id, body, body_len);
            } else if (command == SMB2_CREATE && dir == 1) {
                // FileId 획득 및 매핑
                handle_create_response(conn, msg_id, body, body_len);
            }
        }
        
        // 다음 명령어가 없으면 종료
        if (next_cmd == 0) break;
        offset += next_cmd; // 다음 명령어로 이동
    }
}

/* SMB1 지원용 헬퍼 함수 (파일 ID 생성) */
static void create_file_id_smb1(const connection_t *conn, uint16_t fid, uint8_t file_id[16]) {
    memset(file_id, 0, 16);
    file_id[0] = (uint8_t)(fid & 0xFF);
    file_id[1] = (uint8_t)((fid >> 8) & 0xFF);
    memcpy(&file_id[2], &conn->key.cli_ip, 4);
    memcpy(&file_id[6], &conn->key.cli_port, 2);
    memcpy(&file_id[8], &conn->key.srv_ip, 4);
    memcpy(&file_id[12], &conn->key.srv_port, 2);
}

/* SMB1 메시지 파싱 */
void parse_smb1_message(connection_t *conn, int dir, const uint8_t *msg, size_t len) {
    if (len < 32) return;
    if (!(msg[0] == 0xFF && msg[1] == 'S' && msg[2] == 'M' && msg[3] == 'B')) return;
    uint8_t command = msg[4];
    uint8_t word_count = msg[32];
    const uint8_t *params = msg + 33;
    
    // SMB1은 WRITE 명령만 처리 (파일명 복구 미지원)
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
