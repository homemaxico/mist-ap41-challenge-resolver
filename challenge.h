#ifndef CHALLENGE_H
#define CHALLENGE_H


#include <stddef.h>
#include <stdint.h>

#define MAC_ADDRESS_LEN 0x11 // 16 + 1 null carachter

#define DEVELOPER_MSG_1 "Cm7nkp2X4cMfKuw0"
#define DEVELOPER_MSG_2 "fqxWAIytIQt26vkU"
#define MSG_1 "sr7Krl7tkajVBowS"
#define MSG_2 "ZuSX01QGh8PJq0Na"
#define MSG_TEXT_LEN 0x10

#define DEVELOPER_RANDOM_LEN 0x10
#define RANDOM_LEN 0x20

#define DEVELOPER_CHALLENGE_LEN 49 // 48 + 1 NULL carachter
#define DEVELOPER_ANSWER_LEN 48  // 0x10 random bits from a mist AP41 challenge + 0x20 bytes SHA256 HMAC  



/*
 * Generate a response for a mist AP41 developer challenge .
 *
 * Parameters:
 * - developer_challenge: base64 encoded challange from mistAP41 (with or withouth a initial 'B')
 * - sha256_stdin_key = 16 bits developer key, format deadbeefdeadbeefdeadbeeefdeadbeef
 *
 * Returns:
 * - unsigned char * final_developer_answer (48), base64 encode answer to the developer challenge on success.
 * - NULL on error
 */
unsigned char * developer_answer(char*  developer_challange,  char* sha256_stdin_key, uint8_t* info);


/*
 * Generate a SHA256 HMAC digest .
 *
 * Parameters:
 * - key: key to encode the msg. If the key is NULL it gets read from the eeprom file, address 0x400, len 0x10
 * - key_len: len of the key
 * - msg : message for the HHMAC 
 * - msg_len: len of the message 
 *
 * Returns:
 * - unsiged char* result on success
 * - NULL on error
 */
unsigned char *get_sha256(const unsigned char *key, size_t key_len, 
                          const unsigned char *msg, size_t msg_len, 
                          size_t *out_len);


// Base64 decoding function
size_t base64_decode(const char *in, unsigned char *out, size_t out_len);

// Base64 encoding function
char *base64_encode(const unsigned char *in, size_t in_len);

// Transforms a string of hex numbers to bytes 
unsigned char* hex_string_to_bytes(const char* hex_string, size_t* out_len);


#endif /* CHALLENGE_H */