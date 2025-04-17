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


unsigned char *base64_encode(const unsigned char *input, size_t length) {
    size_t output_len = 4 * ((length + 2) / 3);  // Calculate required output buffer size
    unsigned char *encoded_data = calloc(output_len ,sizeof(int));  
    
    EVP_EncodeBlock(encoded_data, input, length);
    encoded_data[output_len] = '\0';  // Add null terminator
    
    return encoded_data;
}


unsigned char* hex_string_to_bytes(const char* hex_string, size_t* out_len) {
    size_t len = strlen(hex_string);
    if (len % 2 != 0) {
        fprintf(stderr, "Error: Hex string %s must have an even number of characters \n", hex_string);
        return NULL;
    }
    
    *out_len = len / 2;
    unsigned char* bytes = calloc(*out_len, sizeof(int));
    unsigned char* bit = calloc(1, sizeof(int));
    if (!bytes) {
        fprintf(stderr, "Error: Couldn't allocate memory\n");
        return NULL;
    }
    
    for (size_t i = 0; i < *out_len; i++) {      
        
        char b1_test[3] = {hex_string[i*2+1], '\0'};
        char byte_str[3] = {hex_string[i*2], hex_string[i*2+1], '\0'};
        bit[0] = (unsigned char)strtol(b1_test, NULL, 16);
        bytes[i] = (unsigned char)strtol(byte_str, NULL, 16);
        
        if( (bytes[i] == '\0' || bit[0] == '\0') && ( strcmp(byte_str,"00") != 0 ) ){
            fprintf(stderr, "Error: hex string %s contains an invalid character %s at position %d\n",hex_string, byte_str, (int)i);
            return NULL;
        }
    }
    
    return bytes;
}

unsigned char *get_sha256(const unsigned char *key, size_t key_len, 
                          const unsigned char *msg, size_t msg_len) {
    unsigned char *result = calloc(SHA256_DIGEST_LENGTH, sizeof(int));
    unsigned char *sha256_key = (unsigned char *)key;    
    
    HMAC(EVP_sha256(), sha256_key, key_len, msg, msg_len, result, NULL);
    free(sha256_key);
    
    return result;
}


unsigned char * developer_answer(char * developer_challenge, char* sha256_key, uint8_t* info){       
    // Extract mac address , right after characters "D|" 
    unsigned char mac_address[MAC_ADDRESS_LEN];
    memcpy(mac_address, developer_challenge+2, MAC_ADDRESS_LEN);
    mac_address[MAC_ADDRESS_LEN] = '\0';

    if (*info == 1){
        printf("Mac address: ");
        printf((char*)&mac_address);
        printf("\n");
    }

    // Compose the challenge msg
    unsigned char  answer_developer_msg[DEVELOPER_MSG_LEN];
    memcpy(answer_developer_msg, DEVELOPER_SECRET_1, SECRET_LEN);
    memcpy(answer_developer_msg + SECRET_LEN, mac_address, MAC_ADDRESS_LEN);
    memcpy(answer_developer_msg + (SECRET_LEN + MAC_ADDRESS_LEN), DEVELOPER_SECRET_2, SECRET_LEN);
    answer_developer_msg[DEVELOPER_MSG_LEN] = '\0';

    if (*info == 1){
        printf("Developer answer: ");
        printf((char*)answer_developer_msg);
        printf("\n");
    }
        
    // 1st Generation : SHA256 digest with the eeprom key. 
    size_t sha256_answer_first_len = SHA256_DIGEST_LENGTH;

    if ( sha256_key != NULL){
        // Extract random number from the challenge 
        unsigned char *random_from_mist = calloc(DEVELOPER_RANDOM_LEN, sizeof(int));
        memcpy(random_from_mist, developer_challenge + 30, DEVELOPER_RANDOM_LEN);
        memcpy(final_developer_answer, random_from_mist, DEVELOPER_RANDOM_LEN);
        
        if (*info == 1){
            printf("Random number from mist: ");
                for (int i = 0; i < 16; i++) {
                    printf("%02x", random_from_mist[i]);
                }
            printf("\n");
        }

        unsigned char * msg = random_from_mist;
        unsigned char *sha256_answer_first = get_sha256((unsigned char*)sha256_key, strlen(sha256_key), msg, DEVELOPER_RANDOM_LEN);
        free(msg);
    
        if (!sha256_answer_first) {
            fprintf(stderr, "Failed to calculate first SHA256 HMAC\n");
            free(sha256_answer_first);
            return NULL;
        }

        // 2nd Generation : SHA digest using the first result as key
        size_t sha256_answer_2nd_len = SHA256_DIGEST_LENGTH;
        unsigned char *sha256_answer_2nd = get_sha256(sha256_answer_first, sha256_answer_first_len, 
                                                    answer_developer_msg, DEVELOPER_MSG_LEN);
        
        memcpy(final_developer_answer + DEVELOPER_RANDOM_LEN, sha256_answer_2nd, sha256_answer_2nd_len);
        
        free(sha256_answer_2nd);
        return final_developer_answer;

    }else{
        fprintf(stderr, "Empty SHA256 key\n");
        return NULL;
    }
}


  unsigned char * generate_developer_challenge( char* mac_address, char* random_from_stdin, uint8_t* info){
    //Compose the msg
    char *user = "developer";
    unsigned char *developer_msg = calloc(DEVELOPER_CHALLENGE_LEN, sizeof(int));
    if (developer_msg == NULL){
        return NULL;
    }

    developer_msg[0] = 'D';
    developer_msg[1] = '|';
    memcpy(developer_msg+2, mac_address, MAC_ADDRESS_LEN);
    developer_msg[MAC_ADDRESS_LEN+2] = '|';
    memcpy(developer_msg+(MAC_ADDRESS_LEN+3), user, strlen(user));
    memcpy(developer_msg+(4+MAC_ADDRESS_LEN+sizeof(user)), "|", 2); 
    
    //random number 
    unsigned char *random_for_mist = malloc(DEVELOPER_RANDOM_LEN);

    if (random_from_stdin == NULL){
        char * file = "/dev/urandom";
        FILE *f = fopen(file, "rb");
        if (!f) {
            perror("Failed to open urandom device");
            return NULL;
        }
        fread(random_for_mist, 1, DEVELOPER_RANDOM_LEN, f);
        fclose(f);
    }else{
        random_for_mist = (unsigned char*)random_from_stdin;
    }

    memcpy(developer_msg+(MAC_ADDRESS_LEN + 4 + strlen(user)),random_for_mist, DEVELOPER_RANDOM_LEN);

    if (*info == 1 && random_from_stdin == NULL){
        printf("random for mist: ");
        for (int i = 0; i < 16; i++) {
            printf("%02x", random_for_mist[i]);
        }
        printf("\n");
    }
    return developer_msg;
}