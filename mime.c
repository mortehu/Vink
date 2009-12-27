#include <ctype.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>

#include "mail-internal.h"

enum content_type
{
    ct_text_plain,
    ct_message_rfc822,
    ct_multipart_mixed,
    ct_multipart_alternative,
    ct_multipart_related,
    ct_multipart_signed,
    ct_multipart_other,
    ct_other
};

enum content_transfer_encoding
{
    cte_quoted_printable,
    cte_base64,
    cte_literal
};

#define MIN(a,b) ((a) < (b) ? (a) : (b))

void mime_parse_content_type(const char* cts, char* type, size_t type_size,
                             char* subtype, size_t subtype_size,
                             char* charset, size_t charset_size,
                             char* filename, size_t filename_size,
                             char* part_delimiter, size_t part_delimiter_size)
{
    const char* type_delim = strchr(cts, '/');
    size_t type_len;

    if (!type_delim)
        type_delim = cts;

    type_len = type_delim - cts;

    if (type_len >= type_size)
        type_len = type_size - 1;

    strncpy(type, cts, type_len);
    type[type_len] = 0;

    size_t subtype_len = strspn(type_delim + 1, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-");

    if (subtype_len >= subtype_size)
        subtype_len = subtype_size - 1;

    strncpy(subtype, type_delim + 1, subtype_len);
    subtype[subtype_len] = 0;

    char* arg = strchr(type_delim, ';');

    while (arg && *arg)
    {
        char* arg_end;

        ++arg;

        while (isspace(*arg))
            ++arg;

        if (!*arg)
            break;

        arg_end = strchr(arg + 1, ';');

        if (!arg_end)
            arg_end = strchr(arg + 1, 0);

        char* arg_delim = strchr(arg, '=');

        if (!arg_delim)
            break;

        char* key = strndupa(arg, arg_delim - arg);
        char* value = strndupa(arg_delim + 1, arg_end - arg_delim - 1);

        rtrim(value);

        if (value[0] == '"' && value[strlen(value) - 1] == '"')
        {
            value[strlen(value) - 1] = 0;
            ++value;
        }

        if (part_delimiter && !strcasecmp(key, "boundary"))
        {
            strncpy(part_delimiter, value, part_delimiter_size);
            part_delimiter[part_delimiter_size - 1] = 0;
        }
        else if (filename && !strcasecmp(key, "name"))
        {
            if (strchr(value, '/'))
                strncpy(filename, strrchr(value, '/') + 1, filename_size);
            else
                strncpy(filename, value, filename_size);

            filename[filename_size - 1] = 0;
        }
        else if (!strcasecmp(key, "charset"))
        {
            strncpy(charset, value, charset_size);
            charset[charset_size - 1] = 0;
        }

        arg = arg_end;
    }
}

void mime_parse_content_disposition(const char* arg, char* filename, size_t filename_size)
{
    while (arg && *arg)
    {
        char* arg_end;

        ++arg;

        while (isspace(*arg))
            ++arg;

        if (!*arg)
            break;

        arg_end = strchr(arg + 1, ';');

        if (!arg_end)
            arg_end = strchr(arg + 1, 0);

        char* arg_delim = strchr(arg, '=');

        if (!arg_delim)
            break;

        char* key = strndupa(arg, arg_delim - arg);
        char* value = strndupa(arg_delim + 1, arg_end - arg_delim - 1);

        rtrim(value);

        if (value[0] == '"' && value[strlen(value) - 1] == '"')
        {
            value[strlen(value) - 1] = 0;
            ++value;
        }

        if (filename && !strcasecmp(key, "filename"))
        {
            if (strchr(value, '/'))
                strncpy(filename, strrchr(value, '/') + 1, filename_size);
            else
                strncpy(filename, value, filename_size);

            filename[filename_size - 1] = 0;
        }

        arg = arg_end;
    }
}

void mime_sanitize(struct mime_message* result, const char* input, size_t input_size, int flags)
{
    char part_delimiter[256] = { 0 };
    char filename[64] = { 0 };
    char type[32] = "text";
    char subtype[32] = "plain";
    char charset[16] = { 0 };

    struct tuple* headers;
    size_t header_count;
    const char* end;
    const char* body;
    size_t i;
    int content_type_idx = -1;
    int content_transfer_encoding_idx = -1;
    int content_disposition_idx = -1;

    end = input + input_size;

    parse_headers(input, end, &headers, &header_count, &body);

    for (i = 0; i < header_count; ++i)
    {
        if (content_type_idx == -1 && !strncasecmp(headers[i].key, "content-type", headers[i].key_size))
            content_type_idx = i;
        else if (content_transfer_encoding_idx == -1 && !strncasecmp(headers[i].key, "content-transfer-encoding", headers[i].key_size))
            content_transfer_encoding_idx = i;
        else if (content_disposition_idx == -1 && !strncasecmp(headers[i].key, "content-disposition", headers[i].key_size))
            content_disposition_idx = i;
    }

    enum content_type ct = ct_other;
    enum content_transfer_encoding cte = cte_literal;

    if (-1 != content_type_idx)
    {
        char* cts = strndupa(headers[content_type_idx].value, headers[content_type_idx].value_size);

        mime_parse_content_type(cts, type, sizeof(type), subtype, sizeof(subtype), charset, sizeof(charset), filename, sizeof(filename), part_delimiter, sizeof(part_delimiter));

        if (!strcasecmp(type, "text"))
        {
            if (!strcasecmp(subtype, "plain"))
                ct = ct_text_plain;
        }
        else if(!strcasecmp(type, "message"))
        {
            if(!strcasecmp(subtype, "rfc822"))
                ct = ct_message_rfc822;
        }
        else if (!strcasecmp(type, "multipart"))
        {
            if (!strcasecmp(subtype, "mixed"))
                ct = ct_multipart_mixed;
            else if (!strcasecmp(subtype, "alternative"))
                ct = ct_multipart_alternative;
            else if (!strcasecmp(subtype, "related"))
                ct = ct_multipart_related;
            else if (!strcasecmp(subtype, "signed"))
                ct = ct_multipart_signed;
            else
                ct = ct_multipart_other;
        }
    }
    else
        ct = ct_text_plain;

    if (!charset[0])
        strcpy(charset, "US-ASCII");

    if (-1 != content_transfer_encoding_idx)
    {
        char* ctes = strndupa(headers[content_transfer_encoding_idx].value, headers[content_transfer_encoding_idx].value_size);
        rfc2822_unfold(ctes);

        if (!strcasecmp(ctes, "quoted-printable"))
            cte = cte_quoted_printable;
        else if (!strcasecmp(ctes, "base64"))
            cte = cte_base64;
    }

    if (-1 != content_disposition_idx)
    {
        char* cd = strndupa(headers[content_disposition_idx].value, headers[content_disposition_idx].value_size);

        mime_parse_content_disposition(cd, filename, sizeof(filename));
    }

    if (flags & MIME_INCLUDE_HEADERS)
    {
        for (i = 0; i < header_count; ++i)
        {
            char* decoded_header;
            char* header = malloc(headers[i].value_size + 1);
            memcpy(header, headers[i].value, headers[i].value_size);
            header[headers[i].value_size] = 0;

            if (flags & MIME_EXCLUDE_NOISE_HEADERS)
            {
                static const char* important_headers[] = { "subject", "from", "to", "cc", "date" };

                size_t j;

                for (j = 0; j < ARRAY_SIZE(important_headers); ++j)
                {
                    if (   strlen(important_headers[j]) == headers[i].key_size
                        && !strncasecmp(important_headers[j], headers[i].key, headers[i].key_size))
                        break;
                }

                if (j == ARRAY_SIZE(important_headers))
                {
                    free(header);

                    continue;
                }
            }

            if (!strncasecmp(headers[i].key, "subject", headers[i].key_size))
                rfc2822_unfold(header);

            if (-1 == rfc2047_decode(header, &decoded_header))
                decoded_header = header;

            char* buf = 0;

            if (flags & MIME_EXCLUDE_HEADER_NAMES)
                asprintf(&buf, "%s\n", decoded_header);
            else
                asprintf(&buf, "%.*s: %s\n", (int)headers[i].key_size, headers[i].key, decoded_header);

            size_t offset = result->text_size;

            result->text_size += strlen(buf);
            result->text = realloc(result->text, result->text_size);

            memcpy(result->text + offset, buf, result->text_size - offset);

            free(buf);

            if (decoded_header != header)
                free(decoded_header);
            free(header);
        }

        ++result->text_size;
        result->text = realloc(result->text, result->text_size);
        result->text[result->text_size - 1] = '\n';
    }

    if (   ct == ct_multipart_mixed
        || ct == ct_multipart_alternative
        || ct == ct_multipart_related
        || ct == ct_multipart_signed
        || ct == ct_multipart_other)
    {
        if (!part_delimiter[0])
            return;

        size_t part_delimiter_len = strlen(part_delimiter);

        const char* i;
        const char* part_begin = 0;
        const char* part_end = 0;

        for (i = body; i < end - part_delimiter_len - 2; ++i)
        {
            if ((i == body || *(i - 1) == '\n')
            && *i == '-' && *(i + 1) == '-'
            && !memcmp(i + 2, part_delimiter, part_delimiter_len))
            {
                if (part_begin)
                {
                    part_end = i;

                    if (part_begin != part_end)
                        mime_sanitize(result, part_begin, part_end - part_begin, flags & MIME_RECURSIVE_FLAGS);
                }

                part_begin = i + part_delimiter_len + 2;

                while (isspace(*part_begin) && *part_begin != '\n')
                    ++part_begin;

                if (*part_begin == '\n')
                    ++part_begin;
            }
        }
    }
    else if (ct == ct_text_plain || (flags & MIME_INCLUDE_ATTACHMENTS))
    {
        const char* decoded_body = body;
        size_t body_size = end - body;
        size_t offset = result->text_size;

        if (cte == cte_quoted_printable)
        {
            char* tmp = malloc(body_size);
            const char* i = body;
            char* o = tmp;

            while (i != end)
            {
                if (*i == '=' && i + 2 < end)
                {
                    if (isspace(i[1]))
                        i += 2;
                    else
                    {
                        if (i[1] >= '0' && i[1] <= '9')
                            *o = (i[1] - '0') << 4;
                        else
                            *o = (i[1] - 'A' + 0xA) << 4;

                        if (i[2] >= '0' && i[2] <= '9')
                            *o |= (i[2] - '0');
                        else
                            *o |= (i[2] - 'A' + 0xA);

                        ++o;
                        i += 3;
                    }
                }
                else
                    *o++ = *i++;
            }

            body_size = o - tmp;
            decoded_body = tmp;
        }
        else if (cte == cte_base64)
        {
            char* tmp = malloc(body_size);
            int result;

            result = base64_decode(tmp, decoded_body, body_size);

            if (result >= 0)
            {
                body_size = result;
                decoded_body = tmp;
            }
        }

        if (strcasecmp(charset, "utf-8") && strcasecmp(charset, "us-ascii"))
        {
            char* tmp;
            size_t new_size;

            if (-1 != convert_to_utf8(decoded_body, body_size, &tmp, &new_size, charset))
            {
                if (decoded_body != body)
                    free((char*) decoded_body);

                decoded_body = tmp;
                body_size = new_size;
            }
        }

        if (ct == ct_text_plain)
        {
            result->text_size += body_size;
            result->text = realloc(result->text, result->text_size);

            memcpy(result->text + offset, decoded_body, body_size);

            offset = result->text_size;
        }

        if (1)
        {
            char* desc;
            size_t i = result->attachment_count++;
            result->attachments = realloc(result->attachments, result->attachment_count * sizeof(struct mime_attachment));

            asprintf(&result->attachments[i].content_type, "%s/%s", type, subtype);

            if (filename[0])
                result->attachments[i].filename = strdup(filename);
            else
                asprintf(&result->attachments[i].filename, "attachment_%04zu.%s", i + 1, subtype);

            result->attachments[i].data = malloc(body_size);
            memcpy(result->attachments[i].data, decoded_body, body_size);

            result->attachments[i].data_size = body_size;
            result->attachments[i].body_offset = offset;

            asprintf(&desc, "[%s %s %'zu bytes]\n",
                     result->attachments[i].filename,
                     result->attachments[i].content_type,
                     result->attachments[i].data_size);

            result->text_size += strlen(desc);
            result->text = realloc(result->text, result->text_size);

            memcpy(result->text + offset, desc, strlen(desc));
            free(desc);
        }

        if (decoded_body != body)
            free((char*) decoded_body);
    }

    if (flags & MIME_NUL_TERMINATE)
    {
        ++result->text_size;
        result->text = realloc(result->text, result->text_size);
        result->text[result->text_size - 1] = 0;
    }

    free(headers);
}

void mime_free(struct mime_message* result)
{
    size_t i;

    for (i = 0; i < result->attachment_count; ++i)
    {
        free(result->attachments[i].content_type);
        free(result->attachments[i].filename);
        free(result->attachments[i].data);
    }

    free(result->attachments);

    free(result->text);

    memset(result, 0, sizeof(struct mime_message));
}

#ifdef MIME_SANITIZE_MAIN
int main(int argc, char** argv)
{
    if (argc != 2)
    {
        fprintf(stderr, "Use: %s <FILE>\n", argv[0]);

        return EXIT_SUCCESS;
    }

    int fd = open(argv[1], O_RDONLY);
    size_t size = lseek(fd, 0, SEEK_END);
    char* buf = malloc(size);
    pread(fd, buf, size, 0);

    struct mime_message message;
    memset(&message, 0, sizeof(struct mime_message));

    mime_sanitize(&message, buf, size, MIME_INCLUDE_HEADERS);

    write(1, message.text, message.text_size);

    return EXIT_SUCCESS;
}
#endif

/*

struct vink_message *
vink_rfc28822_parse(const char *input, size_t size)
{
  struct arena_info arena, *arena_copy;
  struct vink_message *result;
  struct tuples headers;
  const char *end, *body;
  char *tmp;
  size_t i;

  arena_init(&arena);

  result = arena_calloc(&arena, sizeof(*result));

  ARRAY_INIT(&headers);

  end = input + size;

  parse_headers(input, end, &headers, &body);

  result->body_size = end - body;
  tmp = arena_alloc(&arena, result->body_size);
  memcpy(tmp, body, result->body_size);
  result->body = tmp;

  arena_copy = arena_alloc(&arena, sizeof(arena));
  memcpy(arena_copy, &arena, sizeof(arena));
  result->private = arena_copy;

  return result;
}

*/

/* vim: set ts=4 sw=4 et :*/
