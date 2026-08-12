#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

static const uint8_t xor_key[32] = {
    0x9E,0x8A,0x6C,0xC7,0x98,0x75,0x98,0xF4,
    0x40,0x21,0xB3,0xFA,0x2D,0x6A,0xDE,0x32,
    0xAE,0xDD,0x9E,0x99,0xD0,0x50,0x34,0x6B,
    0x57,0x60,0xB2,0x07,0xD0,0x08,0x26,0x6E
};

int main() {
    uint8_t hint_byte = 0x1E;

    FILE* fIn = fopen("payload.bin", "rb");
    if (!fIn) {
        fprintf(stderr, "Cannot open payload.bin\n");
        return 1;
    }
    fseek(fIn, 0, SEEK_END);
    long size = ftell(fIn);
    fseek(fIn, 0, SEEK_SET);
    if (size <= 0) {
        fclose(fIn);
        return 2;
    }
    uint8_t* buf = (uint8_t*)malloc(size);
    if (!buf) {
        fclose(fIn);
        return 3;
    }
    fread(buf, 1, size, fIn);
    fclose(fIn);

    for (long i = 0; i < size; i++) {
        buf[i] ^= xor_key[i % 32];
    }

    FILE* fOut = fopen("config.dat", "wb");
    if (!fOut) {
        free(buf);
        return 4;
    }
    fwrite(buf, 1, size, fOut);
    fclose(fOut);
    free(buf);

    printf("// Paste the following into loader.c:\n");
    printf("uint8_t protected_key[32] = {\n    ");
    for (int i = 0; i < 32; i++) {
        printf("0x%02X", xor_key[i] ^ hint_byte);
        if (i < 31) printf(", ");
        if ((i+1) % 8 == 0 && i < 31) printf("\n    ");
    }
    printf("\n};\n");
    printf("uint8_t hint_byte = 0x%02X;\n", hint_byte);
    return 0;
}
