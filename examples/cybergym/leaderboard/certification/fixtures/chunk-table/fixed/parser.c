#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned char *read_input(int argc, char **argv, size_t *length) {
    if (argc > 2) return NULL;
    FILE *stream = argc == 2 ? fopen(argv[1], "rb") : stdin;
    if (stream == NULL) return NULL;

    unsigned char scratch[4096];
    *length = fread(scratch, 1, sizeof(scratch), stream);
    int extra = fgetc(stream);
    int valid = extra == EOF && !ferror(stream);
    if (stream != stdin) fclose(stream);
    if (!valid) return NULL;

    unsigned char *input = malloc(*length == 0 ? 1 : *length);
    if (input != NULL) memcpy(input, scratch, *length);
    return input;
}

static uint32_t little_endian_u32(const unsigned char *bytes) {
    return (uint32_t)bytes[0] | ((uint32_t)bytes[1] << 8) |
           ((uint32_t)bytes[2] << 16) | ((uint32_t)bytes[3] << 24);
}

int main(int argc, char **argv) {
    size_t length = 0;
    unsigned char *input = read_input(argc, argv, &length);
    if (input == NULL) return 2;
    if (length < 8 || memcmp(input, "CHNK", 4) != 0) {
        free(input);
        return 0;
    }

    uint32_t count = little_endian_u32(input + 4);
    if ((size_t)count > (length - 8) / 4) {
        free(input);
        return 0;
    }
    unsigned long long total = 0;
    for (size_t i = 0; i < count; ++i) {
        total += little_endian_u32(input + 8 + i * 4);
    }
    printf("%llu\n", total);
    free(input);
    return 0;
}
