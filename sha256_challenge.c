#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "eeprom.h"
#include "challenge.h"


void print_usage(const char *program_name) {
    printf("Usage: %s [arguments]\n", program_name);
    printf("Arguments:\n");
    printf("  -F <eeprom_file> 24c64 eeprom dump from a mist AP-41\n");
    printf("  -C <challenge_from_mist> base64 challenge, with or withouth an initial B character\n");
    printf("  -K <16 bit key from a mist AP41> , format deadbeefdeadbeefdeadbeeefdeadbeef \n");
    printf("  -i show info\n");
    printf("  -h Show this help message\n");
    printf("\n-F or -K are mandatory arguments.");
    printf("\n");
}


int main(int argc, char* argv[]) {
    char* challenge_from_stdin = NULL;
    char* eeprom_file_path = NULL;
    char* sha256_stdin_key = NULL; 
    uint8_t info = 0;
    
    if(argc > 1){
        for (int i = 1; i < argc; i++) {
            if ( (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "-H") == 0) && i + 1 <= argc) {
                print_usage(argv[0]);
                return 0;
            }else if (strcmp(argv[i], "-C") == 0) {
                if (i + 1 < argc && strlen(argv[++i]) > 0x10) {
                    challenge_from_stdin = argv[i];
                } else {
                    fprintf(stderr, "Error: -C requires a challenge string\n");
                    print_usage(argv[0]);
                    return 1;
            }
            }else if (strcmp(argv[i], "-F") == 0) {
                eeprom_file_path = argv[++i];
            }else if (strcmp(argv[i], "-K") == 0) {
                sha256_stdin_key = argv[++i];
            }else if (strcmp(argv[i], "-i") == 0) {
                info = 1;
            }else{
                fprintf(stderr, "Error: invalid %s option\n", argv[i]);
                print_usage(argv[0]);
                return 1;
            } 
        }
    }

    if (challenge_from_stdin != NULL && (eeprom_file_path != NULL || sha256_stdin_key != NULL)){
        unsigned char decoded_challenge[256] = "\0";    
        // check for initial 'B' character
        if (*challenge_from_stdin == 'B'){
            challenge_from_stdin = challenge_from_stdin+1;
        }
        base64_decode(challenge_from_stdin, decoded_challenge, sizeof(decoded_challenge));

        if (memcmp(decoded_challenge, "D",1) == 0){            
            
            char * developer_key = NULL;
            if (eeprom_file_path != NULL){
                developer_key = (char*)get_eeprom(eeprom_file_path);                
                if (info == 1){
                    printf("Challenge type D (Developer)\n");
                    printf("eeprom key: ");
                    for (int i = 0; i < KEY_LEN; i++) {
                        printf("%x",(unsigned char)developer_key[i]);
                    }
                    printf("\n");                
                }
                if (!developer_key) {
                    printf("Error getting the key from the eeprom\n");
                    return 1;
                }
            
            }else{
                size_t key_len = KEY_LEN;
                developer_key = (char*) hex_string_to_bytes(sha256_stdin_key, &key_len);
            }

            unsigned char * final_developer_answer = developer_answer((char*)decoded_challenge, developer_key, &info);
            // Base64 encode final answer
            char *b64_final_answer = base64_encode(final_developer_answer, DEVELOPER_ANSWER_LEN);
            if (info == 1){
                printf("Developer Answer: B%s\n", b64_final_answer);
            }else{
                printf("B%s\n", b64_final_answer);
            }
            free(developer_key);
        
        }else if (memcmp(decoded_challenge, "A",1 == 1)){
            
            printf("Challenge type A not supported \n");
            return 1;
        }

    }else{
        print_usage(argv[0]);
        return 0;
    }   
    return 0;
}
