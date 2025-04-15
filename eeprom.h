#ifndef EEPROM_H
#define EEPROM_H


#include <stddef.h>
#include <stdint.h>

#define KEY_OFFSET 0x400
#define KEY_LEN 0x10
#define MIN_EEPROM_PATH_LENGTH 2 // at least one character + NULL 


unsigned char *get_key_from_eeprom(const char* file);

#endif /* EEPROM_H */