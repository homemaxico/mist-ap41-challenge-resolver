#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "eeprom.h"


unsigned char *get_key_from_eeprom(const char* file) {
    FILE *f = fopen(file, "rb");
    if (!f) {
        perror("Failed to open EEPROM file");
        return NULL;
    }
    
    fseek(f, 0, SEEK_END);
    long file_size = ftell(f);
    rewind(f);
    
    if (file_size < (KEY_OFFSET+KEY_LEN)) {
        fclose(f);
        fprintf(stderr, "EEPROM file too small\n");
        return NULL;
    }
    
    unsigned char *bin_eeprom = malloc(file_size);
    fread(bin_eeprom, 1, file_size, f);
    fclose(f);
    
    unsigned char *sha256_key = malloc(KEY_LEN);
    memcpy(sha256_key, bin_eeprom+KEY_OFFSET, KEY_LEN);
    
    free(bin_eeprom);
    return sha256_key;
}