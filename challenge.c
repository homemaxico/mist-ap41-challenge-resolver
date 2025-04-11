#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include "challenge.h"

 
unsigned char final_developer_answer[DEVELOPER_ANSWER_LEN]; 


size_t base64_decode(const char *in, unsigned char *out, size_t out_len) {
    BIO *b64, *bmem;
    
    b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bmem = BIO_new_mem_buf(in, -1);
    bmem = BIO_push(b64, bmem);
    
    size_t len = BIO_read(bmem, out, out_len);
    
    BIO_free_all(bmem);
    
    return len;
}

char *base64_encode(const unsigned char *in, size_t in_len) {
    BIO *bmem, *b64;
    BUF_MEM *bptr;
    
    b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bmem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, bmem);
    
    BIO_write(b64, in, in_len);
    BIO_flush(b64);
    BIO_get_mem_ptr(b64, &bptr);
    
    char *buff = malloc(bptr->length + 1);
    memcpy(buff, bptr->data, bptr->length);
    buff[bptr->length] = '\0';
    
    BIO_free_all(b64);
    
    return buff;
}

unsigned char* hex_string_to_bytes(const char* hex_string, size_t* out_len) {
    size_t len = strlen(hex_string);
    if (len % 2 != 0) {
        // Hex string must have an even number of characters
        return NULL;
    }
    
    *out_len = len / 2;
    unsigned char* bytes = malloc(*out_len);
    if (!bytes) {
        return NULL;
    }
    
    for (size_t i = 0; i < *out_len; i++) {
        char byte_str[3] = {hex_string[i*2], hex_string[i*2+1], '\0'};
        bytes[i] = (unsigned char)strtol(byte_str, NULL, 16);
    }
    
    return bytes;
}

unsigned char *get_sha256(const unsigned char *key, size_t key_len, 
                          const unsigned char *msg, size_t msg_len, 
                          size_t *out_len) {
    unsigned char *result = malloc(SHA256_DIGEST_LENGTH);
    *out_len = SHA256_DIGEST_LENGTH;
    
    unsigned char *sha256_key = (unsigned char *)key;    
    HMAC(EVP_sha256(), sha256_key, key_len, msg, msg_len, result, NULL);
    
    if (key == NULL) {
        free(sha256_key);
    }
    
    return result;
}


unsigned char * developer_answer(char * developer_challenge, char* sha256_key, uint8_t* info){
       
    // Extract mac address , right after characters "A|" 
    // TODO : add case for "test" mac address, from console_login -t 
    unsigned char mac_address[MAC_ADDRESS_LEN];
    memcpy(mac_address, developer_challenge+2, (strlen(developer_challenge)-2));
    mac_address[sizeof(mac_address)] = '\0';

    if (*info == 1){
        printf("Mac address: ");
        printf((char*)&mac_address);
        printf("\n");
    }

    // Compose the challenge msg
    unsigned char  developer_challenge_answer[DEVELOPER_CHALLENGE_LEN];
    memcpy(developer_challenge_answer, DEVELOPER_SECRET_1, SECRET_LEN);
    memcpy(developer_challenge_answer + SECRET_LEN, mac_address, MAC_ADDRESS_LEN);
    memcpy(developer_challenge_answer + (SECRET_LEN + MAC_ADDRESS_LEN), DEVELOPER_SECRET_2, SECRET_LEN);
    developer_challenge_answer[DEVELOPER_CHALLENGE_LEN] = '\0';

    if (*info == 1){
        printf("Challenge answer: ");
        printf((char*)developer_challenge_answer);
        printf("\n");
    }
        
    // 1st Generation : SHA256 digest with the eeprom key. 
    size_t sha256_answer_first_len;
    unsigned char *sha256_answer_first = malloc(0x20);

    if ( sha256_key != NULL){
        // Extract random from mist 
        unsigned char *random_from_mist = malloc(DEVELOPER_RANDOM_LEN);
        memcpy(random_from_mist, developer_challenge + 30, DEVELOPER_RANDOM_LEN);
        memcpy(final_developer_answer, random_from_mist, 16);
        
        if (*info == 1){
            printf("Random number from mist: ");
                for (int i = 0; i < 16; i++) {
                    printf("%02x", random_from_mist[i]);
                }
            printf("\n");
        }

        unsigned char * msg = (unsigned char *)random_from_mist;
        sha256_answer_first = get_sha256((unsigned char*)sha256_key, strlen(sha256_key), msg, DEVELOPER_RANDOM_LEN, &sha256_answer_first_len);
        free(msg);
    }
    
    if (!sha256_answer_first) {
        fprintf(stderr, "Failed to calculate first SHA256\n");
        return NULL;
    }

    // 2nd Generation : SHA digest using the first result as key
    size_t sha256_answer_2nd_len;
    unsigned char *sha256_answer_2nd = get_sha256(sha256_answer_first, sha256_answer_first_len, 
                                                developer_challenge_answer, DEVELOPER_CHALLENGE_LEN, 
                                                &sha256_answer_2nd_len);
    
    memcpy(final_developer_answer + 16, sha256_answer_2nd, 32);
    
    free(sha256_answer_first);

    return final_developer_answer;
}


