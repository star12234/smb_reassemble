#include "smb_reassemble.h"

/* * file_ctx_t: 현재 열려있는 파일의 핸들 정보를 저장
 * 용도: 매번 fopen/fclose를 하면 느리므로, 한 번 열어둔 파일 포인터(fp)를 재사용하기 위함.
 */
typedef struct file_ctx {
    uint8_t file_id[16];    // 파일 ID (검색 키)
    FILE *fp;               // 열려있는 파일의 포인터 (fwrite에 사용)
    char *path;             // 현재 열려있는 파일의 경로
    struct file_ctx *next;  // 리스트 관리를 위한 포인터
} file_ctx_t;

static file_ctx_t *open_files = NULL; // 열려있는 모든 파일 리스트의 헤드

/*
 * global_file_names
 *
 *  여러 SMB 연결에서 동일한 파일 ID를 사용하는 경우가 있고, 매핑은 CREATE 응답이
 *  하나의 연결에서 온 뒤 다른 연결의 WRITE 요청에서 사용될 수 있습니다. 기존
 *  구현은 connection_t 구조체 내의 file_names 리스트에만 저장했지만, 매핑을
 *  발견하지 못하는 경우가 발생했습니다. 이를 해결하기 위해 전역 매핑 리스트를
 *  추가하여 모든 연결에서 공통으로 참조하도록 합니다.
 */
static file_name_map_t *global_file_names = NULL;

/*
 * utf16le_to_utf8
 * 역할: SMB 패킷에 있는 2바이트 문자열(UTF-16)을 C언어 문자열(ASCII/UTF-8)로 변환
 * 변수 설명:
 * - data: 변환할 원본 바이트 배열 포인터
 * - byte_len: 원본 데이터의 길이 (바이트 단위)
 * - char_count: 글자 수 (바이트 길이 / 2)
 * - out: 변환된 문자열을 저장할 메모리 공간 (리턴값)
 */
/*
 * utf16le_to_utf8
 *
 * 기존 구현은 UTF‑16 코드 포인트의 하위 바이트만 취해 저장했기 때문에
 * 한글, 한자 등의 문자가 모두 깨지는 문제가 있었다. 이 함수는 UTF‑16LE
 * 데이터를 올바르게 UTF‑8 문자열로 변환한다. 서러게이트 페어를 지원하며
 * 잘못된 시퀀스는 U+FFFD (Replacement Character)로 대체한다.
 */
char *utf16le_to_utf8(const uint8_t *data, size_t byte_len) {
    if (!data || byte_len == 0 || (byte_len % 2) != 0) {
        return strdup("");
    }

    size_t in_chars = byte_len / 2;
    // Worst case: each UTF‑16 code unit becomes 3 UTF‑8 bytes, surrogate pairs become 4.
    // Allocate generously: 4 bytes per code unit + 1 for null terminator.
    size_t out_cap = (in_chars * 4) + 1;
    char *out = (char *)calloc(out_cap, 1);
    if (!out) return NULL;
    size_t out_len = 0;

    for (size_t i = 0; i < in_chars; i++) {
        // Read little‑endian 16‑bit value
        uint16_t w1 = (uint16_t)data[i * 2] | ((uint16_t)data[i * 2 + 1] << 8);
        uint32_t codepoint = 0;

        // Check for surrogate pairs
        if (w1 >= 0xD800 && w1 <= 0xDBFF) {
            // High surrogate; ensure there is a following low surrogate
            if (i + 1 < in_chars) {
                uint16_t w2 = (uint16_t)data[(i + 1) * 2] | ((uint16_t)data[(i + 1) * 2 + 1] << 8);
                if (w2 >= 0xDC00 && w2 <= 0xDFFF) {
                    codepoint = 0x10000 + (((uint32_t)w1 - 0xD800) << 10) + ((uint32_t)w2 - 0xDC00);
                    i++; // consume the low surrogate
                } else {
                    // Invalid surrogate pair; use replacement character
                    codepoint = 0xFFFD;
                }
            } else {
                // Truncated surrogate pair; replacement character
                codepoint = 0xFFFD;
            }
        } else if (w1 >= 0xDC00 && w1 <= 0xDFFF) {
            // Unexpected low surrogate
            codepoint = 0xFFFD;
        } else {
            // Basic Multilingual Plane
            codepoint = w1;
        }

        // Encode codepoint into UTF‑8
        if (codepoint <= 0x7F) {
            // 1 byte: 0xxxxxxx
            if (out_len + 1 >= out_cap) {
                // Expand buffer
                out_cap *= 2;
                char *tmp = realloc(out, out_cap);
                if (!tmp) { free(out); return NULL; }
                out = tmp;
            }
            out[out_len++] = (char)codepoint;
        } else if (codepoint <= 0x7FF) {
            // 2 bytes: 110xxxxx 10xxxxxx
            if (out_len + 2 >= out_cap) {
                out_cap *= 2;
                char *tmp = realloc(out, out_cap);
                if (!tmp) { free(out); return NULL; }
                out = tmp;
            }
            out[out_len++] = (char)(0xC0 | ((codepoint >> 6) & 0x1F));
            out[out_len++] = (char)(0x80 | (codepoint & 0x3F));
        } else if (codepoint <= 0xFFFF) {
            // 3 bytes: 1110xxxx 10xxxxxx 10xxxxxx
            if (out_len + 3 >= out_cap) {
                out_cap *= 2;
                char *tmp = realloc(out, out_cap);
                if (!tmp) { free(out); return NULL; }
                out = tmp;
            }
            out[out_len++] = (char)(0xE0 | ((codepoint >> 12) & 0x0F));
            out[out_len++] = (char)(0x80 | ((codepoint >> 6) & 0x3F));
            out[out_len++] = (char)(0x80 | (codepoint & 0x3F));
        } else if (codepoint <= 0x10FFFF) {
            // 4 bytes: 11110xxx 10xxxxxx 10xxxxxx 10xxxxxx
            if (out_len + 4 >= out_cap) {
                out_cap *= 2;
                char *tmp = realloc(out, out_cap);
                if (!tmp) { free(out); return NULL; }
                out = tmp;
            }
            out[out_len++] = (char)(0xF0 | ((codepoint >> 18) & 0x07));
            out[out_len++] = (char)(0x80 | ((codepoint >> 12) & 0x3F));
            out[out_len++] = (char)(0x80 | ((codepoint >> 6) & 0x3F));
            out[out_len++] = (char)(0x80 | (codepoint & 0x3F));
        }
    }

    // Null terminate
    if (out_len >= out_cap) {
        char *tmp = realloc(out, out_cap + 1);
        if (!tmp) { free(out); return NULL; }
        out = tmp;
        out_cap += 1;
    }
    out[out_len] = '\0';
    return out;
}

/* Forward declaration of ensure_parent_dirs to avoid implicit declaration warnings. */
static void ensure_parent_dirs(const char *full_path);

/* Forward declaration to ensure ensure_parent_dirs is known before use. */
static void ensure_parent_dirs(const char *full_path);

/*
 * sanitize_path
 * 역할: 파일명에 포함된 위험하거나 불필요한 문자 제거 (보안 목적)
 * 변수 설명:
 * - in: 원본 파일명
 * - out: 정제된 파일명이 저장될 버퍼
 * - skip_leading: 경로 맨 앞의 슬래시(/)를 제거하기 위한 플래그
 * - c: 현재 검사 중인 문자 하나
 */
void sanitize_path(const char *in, char *out, size_t out_size) {
    size_t j = 0; // 출력 버퍼(out)의 현재 인덱스
    int skip_leading = 1;
    
    // i: 입력 문자열(in)을 순회하는 인덱스
    for (size_t i = 0; in[i] && j + 1 < out_size; i++) {
        char c = in[i];
        if (c == '\\') c = '/'; // 윈도우 경로 구분자를 리눅스용으로 변경
        if (i == 1 && in[1] == ':') continue; // C: 같은 드라이브 문자 건너뜀
        if (skip_leading && (c == '/' || c == '\\')) continue; // 맨 앞 슬래시 제거
        
        skip_leading = 0; // 첫 글자 이후로는 leading 체크 안 함
        
        // 상위 폴더(..)로 이동하는 해킹 시도 방지
        if (c == '.' && in[i + 1] == '.') {
            i++; 
            if (in[i + 1] == '/' || in[i + 1] == '\\') i++;
            continue;
        }
        // 파일명에 쓸 수 없는 특수문자 제거
        if (c == ':' || c == '*' || c == '?' || c == '"' || c == '<' || c == '>' || c == '|') continue;
        out[j++] = c; // 안전한 문자만 버퍼에 추가
    }
    out[j] = '\0'; // 문자열 끝 알림
}

/*
 * remember_file_name
 * 역할: 복구된 파일명을 메모리에 영구 저장 (나중에 WRITE 패킷이 오면 쓰려고)
 * 변수 설명:
 * - conn: 현재 연결 정보
 * - file_id: 매핑할 키값
 * - orig_name: 원본 파일명
 * - m: 새로 생성하거나 탐색할 매핑 구조체 포인터
 */
void remember_file_name(connection_t *conn, const uint8_t *file_id, const char *orig_name) {
    file_name_map_t *m;
    // 이미 등록된 ID인지 확인
    for (m = conn->file_names; m; m = m->next) {
        if (memcmp(m->file_id, file_id, 16) == 0) return;
    }
    
    char safe[512]; // 정제된 파일명을 담을 임시 버퍼
    sanitize_path(orig_name, safe, sizeof(safe));

    // sanitize_path가 빈 문자열을 반환한 경우 매핑을 만들지 않는다.
    if (safe[0] == '\0') {
        fprintf(stderr, "[WARN] Ignoring empty or invalid filename for mapping\n");
        return;
    }

    // 새 매핑 정보 생성
    m = (file_name_map_t *)calloc(1, sizeof(file_name_map_t));
    memcpy(m->file_id, file_id, 16);
    m->name = strdup(safe);
    /*
     * 매핑은 연결별 리스트(conn->file_names)와 전역 리스트(global_file_names)에
     * 모두 추가한다. 전역 리스트는 다른 연결에서 WRITE 요청이 오더라도
     * 매핑을 찾을 수 있도록 한다.
     */
    m->next = conn->file_names;
    conn->file_names = m;
    // 전역 리스트 앞쪽에 삽입
    file_name_map_t *gm = (file_name_map_t *)calloc(1, sizeof(file_name_map_t));
    memcpy(gm->file_id, file_id, 16);
    gm->name = strdup(safe);
    gm->next = global_file_names;
    global_file_names = gm;

    printf("[INFO] Mapped ID to Name: %s\n", safe);

    /*
     * 이미 이 file_id로 열린 파일이 있는 경우 .bin 파일을 원본 이름으로 변경한다.
     * rename() 호출은 열린 파일에도 적용되므로, 파일 핸들은 그대로 사용할 수 있다.
     */
    for (file_ctx_t *ctx = open_files; ctx; ctx = ctx->next) {
        if (memcmp(ctx->file_id, file_id, 16) == 0) {
            // 새로운 전체 경로 계산
            char new_path[1024];
            snprintf(new_path, sizeof(new_path), "%s/%s", output_dir, safe);
            ensure_parent_dirs(new_path);

            // 현재 경로와 동일한 경우 작업 불필요
            if (ctx->path && strcmp(ctx->path, new_path) == 0) {
                break;
            }
            if (rename(ctx->path, new_path) == 0) {
                printf("[IO] Renamed %s -> %s\n", ctx->path, new_path);
                free(ctx->path);
                ctx->path = strdup(new_path);
            } else {
                perror("rename");
            }
            break;
        }
    }
}

/* 디렉토리 자동 생성 함수 (mkdir -p 와 비슷) */
static void ensure_parent_dirs(const char *full_path) {
    char tmp[1024];
    if (strlen(full_path) >= sizeof(tmp)) return;
    strcpy(tmp, full_path);
    
    // p: 경로 문자열을 탐색하는 포인터
    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') { // 슬래시를 만나면
            *p = '\0';   // 잠시 문자열을 끊고
            mkdir(tmp, 0755); // 여기까지의 경로로 폴더 생성
            *p = '/';    // 다시 슬래시 복구
        }
    }
}

/*
 * write_file_chunk
 * 역할: 실제 데이터를 파일에 쓰는 핵심 함수
 * 변수 설명:
 * - ctx: 파일 핸들 정보를 담은 구조체 포인터 (캐싱용)
 * - path: 파일의 전체 경로를 저장할 문자열 버퍼
 * - m: 파일명 매핑 정보를 찾기 위한 순회용 포인터
 */
void write_file_chunk(connection_t *conn, const uint8_t *file_id, uint64_t offset, const uint8_t *data, size_t len) {
    file_ctx_t *ctx;
    // 1. 이미 열려있는 파일 중에서 찾기
    for (ctx = open_files; ctx; ctx = ctx->next) {
        if (memcmp(ctx->file_id, file_id, 16) == 0) break;
    }
    
    // 2. 없으면 새로 열기
    if (!ctx) {
        char path[1024];
        const file_name_map_t *m;
        const char *name = NULL;
        
        /*
         * 우선 연결별 매핑 테이블을 검색한다. 없다면 전역 매핑 테이블을 검색한다.
         * 일부 경우 CREATE 응답과 WRITE 요청이 다른 연결에서 오기 때문에 전역
         * 리스트를 통해서도 매핑을 확인해야 한다.
         */
        for (m = conn ? conn->file_names : NULL; m; m = m->next) {
            if (memcmp(m->file_id, file_id, 16) == 0) {
                name = m->name;
                break;
            }
        }
        if (!name) {
            for (m = global_file_names; m; m = m->next) {
                if (memcmp(m->file_id, file_id, 16) == 0) {
                    name = m->name;
                    break;
                }
            }
        }

        if (name) {
            // 이름을 찾았으면 그 이름으로 경로 생성
            snprintf(path, sizeof(path), "%s/%s", output_dir, name);
            ensure_parent_dirs(path);
        } else {
            // 못 찾았으면 Hex ID로 이름 생성
            char hexname[33];
            for (int i = 0; i < 16; i++) sprintf(&hexname[i * 2], "%02x", file_id[i]);
            snprintf(path, sizeof(path), "%s/%s.bin", output_dir, hexname);
        }

        ctx = (file_ctx_t *)calloc(1, sizeof(file_ctx_t));
        memcpy(ctx->file_id, file_id, 16);
        ctx->path = strdup(path);
        ctx->fp = fopen(path, "wb"); // 바이너리 쓰기 모드로 파일 오픈

        if (!ctx->fp) {
            fprintf(stderr, "Failed to open %s\n", path);
            free(ctx->path);
            free(ctx);
            return;
        }
        printf("[IO] Created/Opened: %s\n", path);

        ctx->next = open_files;
        open_files = ctx;
    }
    
    // 3. 데이터 쓰기
    fseeko(ctx->fp, (off_t)offset, SEEK_SET); // 정확한 위치로 이동
    fwrite(data, 1, len, ctx->fp); // 데이터 기록
    fflush(ctx->fp); // 버퍼를 비워 즉시 디스크에 저장 (강제 종료 시 데이터 보호)
}

/* 프로그램 종료 시 호출되어 모든 파일을 닫음 */
void close_all_files() {
    for (file_ctx_t *ctx = open_files; ctx; ctx = ctx->next) {
        if (ctx->fp) fclose(ctx->fp);
        if (ctx->path) free(ctx->path);
    }
}
