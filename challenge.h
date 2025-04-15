#ifndef CHALLENGE_H
#define CHALLENGE_H


#include <stddef.h>
#include <stdint.h>

#define MAC_ADDRESS_LEN 17

#define DEVELOPER_SECRET_1 "Cm7nkp2X4cMfKuw0"
#define DEVELOPER_SECRET_2 "fqxWAIytIQt26vkU"
#define SECRET_1 "sr7Krl7tkajVBowS"
#define SECRET_2 "ZuSX01QGh8PJq0Na"
#define SECRET_LEN 0x10

#define DEVELOPER_RANDOM_LEN 0x10
#define RANDOM_LEN 0x20

#define DEVELOPER_MSG_LEN 49 // 48 + 1 NULL carachter
#define DEVELOPER_ANSWER_LEN 48  // 0x10 random bits from a mist AP41 challenge + 0x20 bytes SHA256 HMAC
#define DEVELOPER_CHALLENGE_LEN  46 // 0x20 D|mac|developer| + 0x10 random number
#define MIN_CHALLENGE_LENGTH 2 // Not sure about this




/*
 * Generate a response for a mist AP41 developer challenge .
 *
 * Parameters:
 * - developer_challenge: challenge from mistAP41
 * - sha256_key: 16 bits developer key, format deadbeefdeadbeefdeadbeeefdeadbeef
 * - info: print info messages to stdin, values 0 or 1
 *
 * Returns:
 * - unsigned char * final_developer_answer (48), base64 encode answer to the developer challenge on success.
 * - NULL on error
 */
unsigned char * developer_answer(char*  developer_challenge,  char* sha256_key, uint8_t* info);


/*
 * Generates a mist AP41 developer challenge. 
 *
 * Parameters:
 * - mac_address: addresses separated by '-'
 * - random_for_mist: 16 bit number, format aabbccddeeffaaabacadaeafbabbbcbd. If the value is NULL the number
 *  gets populated from /dev/urandom   
 * - info: print info messages to stdin, values 0 or 1
 *
 * Returns:
 * - unsigned char * final_developer_answer (48), base64 encode answer to the developer challenge on success.
 * - NULL on error
 */
 unsigned char * generate_developer_challenge(char* mac_address, char* random_for_mist, uint8_t* info);


/*
 * Generate a SHA256 HMAC digest .
 *
 * Parameters:
 * - key: key to encode the msg. 
 * - key_len: len of the key
 * - msg : message for the HHMAC 
 * - msg_len: len of the message 
 *
 * Returns:
 * - unsiged char* result on success
 * - NULL on error
 */
unsigned char *get_sha256(const unsigned char *key, size_t key_len, 
                          const unsigned char *msg, size_t msg_len);


// Base64 decoding function
size_t base64_decode(const char *in, unsigned char *out, size_t out_len);

// Base64 encoding function  
unsigned char *base64_encode(const unsigned char *input, size_t length);

// Transforms a string of hex numbers to bytes 
unsigned char* hex_string_to_bytes(const char* hex_string, size_t* out_len);


#endif /* CHALLENGE_H */