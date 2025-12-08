#include "smb_reassemble.h"

typedef struct file_ctx {
    uint8_t file_id[16];
    FILE *fp;
    char *path;
    struct file_ctx *next;
} file_ctx_t;

static file_ctx_t *open_files = NULL;

static file_name_map_t *global_file_names = NULL;

char *utf16le_to_utf8(const uint8_t *data, size_t byte_len) {
    if (!data || byte_len == 0 || (byte_len % 2) != 0) {
        return strdup("");
    }

    size_t in_chars = byte_len / 2;
    size_t out_cap = (in_chars * 4) + 1;
    char *out = (char *)calloc(out_cap, 1);
    if (!out) return NULL;
    size_t out_len = 0;

    for (size_t i = 0; i < in_chars; i++) {
        uint16_t w1 = (uint16_t)data[i * 2] | ((uint16_t)data[i * 2 + 1] << 8);
        uint32_t codepoint = 0;

        if (w1 >= 0xD800 && w1 <= 0xDBFF) {
            if (i + 1 < in_chars) {
                uint16_t w2 = (uint16_t)data[(i + 1) * 2] | ((uint16_t)data[(i + 1) * 2 + 1] << 8);
                if (w2 >= 0xDC00 && w2 <= 0xDFFF) {
                    codepoint = 0x10000 + (((uint32_t)w1 - 0xD800) << 10) + ((uint32_t)w2 - 0xDC00);
                    i++;
                } else {
                    codepoint = 0xFFFD;
                }
            } else {
                codepoint = 0xFFFD;
            }
        } else if (w1 >= 0xDC00 && w1 <= 0xDFFF) {
            codepoint = 0xFFFD;
        } else {
            codepoint = w1;
        }

        if (codepoint <= 0x7F) {
            if (out_len + 1 >= out_cap) {
                out_cap *= 2;
                char *tmp = realloc(out, out_cap);
                if (!tmp) { free(out); return NULL; }
                out = tmp;
            }
            out[out_len++] = (char)codepoint;
        } else if (codepoint <= 0x7FF) {
            if (out_len + 2 >= out_cap) {
                out_cap *= 2;
                char *tmp = realloc(out, out_cap);
                if (!tmp) { free(out); return NULL; }
                out = tmp;
            }
            out[out_len++] = (char)(0xC0 | ((codepoint >> 6) & 0x1F));
            out[out_len++] = (char)(0x80 | (codepoint & 0x3F));
        } else if (codepoint <= 0xFFFF) {
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

    if (out_len >= out_cap) {
        char *tmp = realloc(out, out_cap + 1);
        if (!tmp) { free(out); return NULL; }
        out = tmp;
        out_cap += 1;
    }
    out[out_len] = '\0';
    return out;
}

static void ensure_parent_dirs(const char *full_path);

static void ensure_parent_dirs(const char *full_path);

void sanitize_path(const char *in, char *out, size_t out_size) {
    size_t j = 0;
    int skip_leading = 1;
    
    for (size_t i = 0; in[i] && j + 1 < out_size; i++) {
        char c = in[i];
        if (c == '\\') c = '/';
        if (i == 1 && in[1] == ':') continue;
        if (skip_leading && (c == '/' || c == '\\')) continue;
        
        skip_leading = 0;
        
        if (c == '.' && in[i + 1] == '.') {
            i++; 
            if (in[i + 1] == '/' || in[i + 1] == '\\') i++;
            continue;
        }
        if (c == ':' || c == '*' || c == '?' || c == '"' || c == '<' || c == '>' || c == '|') continue;
        out[j++] = c;
    }
    out[j] = '\0';
}

void remember_file_name(connection_t *conn, const uint8_t *file_id, const char *orig_name) {
    file_name_map_t *m;
    for (m = conn->file_names; m; m = m->next) {
        if (memcmp(m->file_id, file_id, 16) == 0) return;
    }
    
    char safe[512];
    sanitize_path(orig_name, safe, sizeof(safe));

    if (safe[0] == '\0') {
        fprintf(stderr, "[WARN] Ignoring empty or invalid filename for mapping\n");
        return;
    }

    m = (file_name_map_t *)calloc(1, sizeof(file_name_map_t));
    memcpy(m->file_id, file_id, 16);
    m->name = strdup(safe);
    m->next = conn->file_names;
    conn->file_names = m;
    file_name_map_t *gm = (file_name_map_t *)calloc(1, sizeof(file_name_map_t));
    memcpy(gm->file_id, file_id, 16);
    gm->name = strdup(safe);
    gm->next = global_file_names;
    global_file_names = gm;

    printf("[INFO] Mapped ID to Name: %s\n", safe);

    for (file_ctx_t *ctx = open_files; ctx; ctx = ctx->next) {
        if (memcmp(ctx->file_id, file_id, 16) == 0) {
            char new_path[1024];
            snprintf(new_path, sizeof(new_path), "%s/%s", output_dir, safe);
            ensure_parent_dirs(new_path);

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

static void ensure_parent_dirs(const char *full_path) {
    char tmp[1024];
    if (strlen(full_path) >= sizeof(tmp)) return;
    strcpy(tmp, full_path);
    
    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            mkdir(tmp, 0755);
            *p = '/';
        }
    }
}

void write_file_chunk(connection_t *conn, const uint8_t *file_id, uint64_t offset, const uint8_t *data, size_t len) {
    file_ctx_t *ctx;
    for (ctx = open_files; ctx; ctx = ctx->next) {
        if (memcmp(ctx->file_id, file_id, 16) == 0) break;
    }
    
    if (!ctx) {
        char path[1024];
        const file_name_map_t *m;
        const char *name = NULL;
        
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
            snprintf(path, sizeof(path), "%s/%s", output_dir, name);
            ensure_parent_dirs(path);
        } else {
            char hexname[33];
            for (int i = 0; i < 16; i++) sprintf(&hexname[i * 2], "%02x", file_id[i]);
            snprintf(path, sizeof(path), "%s/%s.bin", output_dir, hexname);
        }

        ctx = (file_ctx_t *)calloc(1, sizeof(file_ctx_t));
        memcpy(ctx->file_id, file_id, 16);
        ctx->path = strdup(path);
        ctx->fp = fopen(path, "wb");

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
    
    fseeko(ctx->fp, (off_t)offset, SEEK_SET);
    fwrite(data, 1, len, ctx->fp);
    fflush(ctx->fp);
}

void close_all_files() {
    for (file_ctx_t *ctx = open_files; ctx; ctx = ctx->next) {
        if (ctx->fp) fclose(ctx->fp);
        if (ctx->path) free(ctx->path);
    }
}