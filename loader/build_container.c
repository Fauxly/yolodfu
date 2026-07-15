#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <lz4.h>
#include <lz4hc.h>

enum {
    LOADER_SIZE = 0x200,
    LOADER_COMPRESSED_SIZE_OFFSET = 0x1fc,
};

static uint8_t *read_file(const char *path, size_t *size)
{
    FILE *file = fopen(path, "rb");
    if (!file) {
        fprintf(stderr, "open %s: %s\n", path, strerror(errno));
        exit(1);
    }
    if (fseek(file, 0, SEEK_END) || (*size = (size_t)ftell(file)) == (size_t)-1 ||
        fseek(file, 0, SEEK_SET)) {
        fprintf(stderr, "seek %s failed\n", path);
        exit(1);
    }
    uint8_t *data = malloc(*size ? *size : 1);
    if (!data || fread(data, 1, *size, file) != *size || fclose(file)) {
        fprintf(stderr, "read %s failed\n", path);
        exit(1);
    }
    return data;
}

int main(int argc, char **argv)
{
    if (argc != 4) {
        fprintf(stderr, "usage: %s <loader.bin> <Pongo.bin> <output.bin>\n", argv[0]);
        return 2;
    }

    size_t loader_size, pongo_size;
    uint8_t *loader = read_file(argv[1], &loader_size);
    uint8_t *pongo = read_file(argv[2], &pongo_size);
    if (loader_size != LOADER_SIZE || pongo_size > INT32_MAX) {
        fprintf(stderr, "invalid input sizes: loader=%zu pongo=%zu\n", loader_size, pongo_size);
        return 1;
    }

    int bound = LZ4_compressBound((int)pongo_size);
    uint8_t *compressed = malloc((size_t)bound);
    int compressed_size = LZ4_compress_HC((const char *)pongo, (char *)compressed,
                                          (int)pongo_size, bound, LZ4HC_CLEVEL_MAX);
    if (compressed_size <= 0) {
        fprintf(stderr, "LZ4_compress_HC failed\n");
        return 1;
    }
    uint8_t *roundtrip = malloc(pongo_size ? pongo_size : 1);
    int decompressed_size = LZ4_decompress_safe((const char *)compressed, (char *)roundtrip,
                                                compressed_size, (int)pongo_size);
    if (decompressed_size != (int)pongo_size || memcmp(roundtrip, pongo, pongo_size)) {
        fprintf(stderr, "LZ4 round-trip verification failed\n");
        return 1;
    }

    uint32_t encoded_size = (uint32_t)compressed_size;
    memcpy(loader + LOADER_COMPRESSED_SIZE_OFFSET, &encoded_size, sizeof(encoded_size));
    FILE *output = fopen(argv[3], "wb");
    if (!output || fwrite(loader, 1, loader_size, output) != loader_size ||
        fwrite(compressed, 1, (size_t)compressed_size, output) != (size_t)compressed_size ||
        fclose(output)) {
        fprintf(stderr, "write %s failed\n", argv[3]);
        return 1;
    }

    printf("pongo=%zu compressed=%d container=%zu\n",
           pongo_size, compressed_size, loader_size + (size_t)compressed_size);
    return 0;
}
