#ifndef EEPROM_H
#define EEPROM_H


#include <stddef.h>
#include <stdint.h>

#define KEY_OFFSET 0x400
#define KEY_LEN 0x10


unsigned char *get_eeprom(const char* file);

#endif /* EEPROM_H */