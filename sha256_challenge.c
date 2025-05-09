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
    printf("  -K <16 bit key from a mist AP41> , format deadbeefdeadbeefdeadbeefdeadbeef \n");
    printf("  -G <mac address> generate a mist41 developer challenge for a given mac\n");
    printf("  -R <16 bits random number> for challenge generation, format aabbccddeeffaaabacadaeafbabbbcbd\n");
    printf("  -h Show this help message\n");
    printf("  -i show info\n");
    printf("\n-F or -K are mandatory arguments. if -R is not given the program will generate a random number.");
    printf("\n");
}


int main(int argc, char* argv[]) {
    char* challenge_from_stdin = NULL;
    char* eeprom_file_path = NULL;
    char* sha256_stdin_key = NULL;
    char* mac_adress = NULL; 
    char* random_from_stdin = NULL;
    uint8_t info = 0;
    
    if(argc > 1) {
        for (int i = 1; i < argc; i++) {
            if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "-H") == 0) {
                print_usage(argv[0]);
                return 0;
            } else if (strcmp(argv[i], "-C") == 0) {
                if (i + 1 < argc) {
                    i++;  // Move to the argument value
                    if (strlen(argv[i]) > DEVELOPER_ANSWER_LEN) { 
                        challenge_from_stdin = argv[i];
                    } else {
                        fprintf(stderr, "Error: -C requires a challenge string with length > %d characters\n", 
                                DEVELOPER_ANSWER_LEN);
                        print_usage(argv[0]);
                        return 1;
                    }
                } else {
                    fprintf(stderr, "Error: -C option requires an argument\n");
                    print_usage(argv[0]);
                    return 1;
                }
            } else if (strcmp(argv[i], "-G") == 0) {
                if (i + 1 < argc) {
                    i++;
                    if (strlen(argv[i]) > MAC_ADDRESS_LEN-1) {  
                        mac_adress = argv[i];
                    } else {
                        fprintf(stderr, "Error: -G requires a MAC address with length > %d characters\n", 
                                MAC_ADDRESS_LEN);
                        print_usage(argv[0]);
                        return 1;
                    }
                } else {
                    fprintf(stderr, "Error: -G option requires an argument\n");
                    print_usage(argv[0]);
                    return 1;
                }
            } else if (strcmp(argv[i], "-R") == 0) {
                if (i + 1 < argc) {
                    i++;
                    if (strlen(argv[i]) == (DEVELOPER_RANDOM_LEN*2)) {
                        random_from_stdin = argv[i];
                    } else {
                        fprintf(stderr, "Error: -R requires a 16bit random number of %d characters lenght\n", 
                                DEVELOPER_RANDOM_LEN);
                        print_usage(argv[0]);
                        return 1;
                    }
                } else {
                    fprintf(stderr, "Error: -R option requires an argument\n");
                    print_usage(argv[0]);
                    return 1;
                }
            } else if (strcmp(argv[i], "-F") == 0) {
                if (i + 1 < argc) {
                    i++;
                    if (strlen(argv[i]) > MIN_EEPROM_PATH_LENGTH) {
                        eeprom_file_path = argv[i];
                    } else {
                        fprintf(stderr, "Error: -F requires an eeprom dump file with length > %d characters\n", 
                                MIN_EEPROM_PATH_LENGTH);
                        print_usage(argv[0]);
                        return 1;
                    }
                } else {
                    fprintf(stderr, "Error: -F option requires an argument\n");
                    print_usage(argv[0]);
                    return 1;
                }
            } else if (strcmp(argv[i], "-K") == 0) {
                if (i + 1 < argc) {
                    i++;
                    if (strlen(argv[i]) == KEY_LEN*2) {
                        sha256_stdin_key = argv[i];
                    } else {
                        fprintf(stderr, "Error: -K requires a 16bit key with a length of %d characters\n", 
                                KEY_LEN*2);
                        print_usage(argv[0]);
                        return 1;
                    }
                } else {
                    fprintf(stderr, "Error: -K option requires an argument\n");
                    print_usage(argv[0]);
                    return 1;
                }
            } else if (strcmp(argv[i], "-i") == 0) {
                info = 1;
            } else {
                fprintf(stderr, "Error: invalid option '%s'\n", argv[i]);
                print_usage(argv[0]);
                return 1;
            }
        }
    }

    if (mac_adress != NULL){
        
        char * random_for_mist = NULL;    
        if (random_from_stdin != NULL){
            size_t random_len = DEVELOPER_RANDOM_LEN;
            random_for_mist = (char*) hex_string_to_bytes(random_from_stdin, &random_len);
        }

        if((random_for_mist==NULL && (info==1))){
            fprintf(stderr, "Error: Invalid random number for option -G, continuing using /dev/urandom\n");
        }
        if((random_for_mist==NULL && (info==0))){
            fprintf(stderr, "Error: Invalid random number for option -G, exiting\n");
            return 1;
        }
        
        unsigned char* developer_challenge = generate_developer_challenge(mac_adress, random_for_mist, &info);
        unsigned char * b64_challenge = base64_encode(developer_challenge , DEVELOPER_CHALLENGE_LEN);

        if (info ==1){
            printf("Developer challenge for %s: ", mac_adress );
        }

        printf("B%s\n",b64_challenge);
        free(b64_challenge);
        free(developer_challenge);
        
        return 0;
    }

    if (challenge_from_stdin != NULL && (eeprom_file_path != NULL || sha256_stdin_key != NULL)){
        unsigned char decoded_challenge[DEVELOPER_CHALLENGE_LEN] = "\0";    
        // check for initial 'B' character
        if (*challenge_from_stdin == 'B'){
            challenge_from_stdin = challenge_from_stdin+1;
        }
        base64_decode(challenge_from_stdin, decoded_challenge, sizeof(decoded_challenge));

        if (memcmp(decoded_challenge, "D",1) == 0){            
            unsigned char * developer_key = NULL;
            
            if (eeprom_file_path != NULL){
                
                developer_key = get_key_from_eeprom(eeprom_file_path); 
                if (developer_key == NULL){
                    printf("Error getting the key from the eeprom\n");
                    return -1;
                }               
                
                if (info == 1){
                    printf("Challenge type D (Developer)\n");
                    printf("eeprom key: ");
                    for (int i = 0; i < KEY_LEN; i++) {
                        printf("%02x",developer_key[i]);
                    }
                    printf("\n");                
                }
            
            }else{
                size_t key_len = KEY_LEN;
                developer_key =  hex_string_to_bytes(sha256_stdin_key, &key_len);
                if (developer_key == NULL){
                    if (info == 1){
                        printf("Error: Invalid key %s for option -K, exiting\n", sha256_stdin_key);
                    }
                    return 1;
                }
            }

            unsigned char * final_developer_answer = developer_answer((char*)decoded_challenge, (char*)developer_key, &info);
            if (final_developer_answer == NULL){
                fprintf(stderr, "Error: Couldn't get a developer answer for %s \n", challenge_from_stdin);
                return 1;
            }
            // Base64 encode final answer
            unsigned char *b64_final_answer = base64_encode(final_developer_answer, DEVELOPER_ANSWER_LEN);
            if (info == 1){
                printf("------------------------\n");
                printf("Developer answer: ");
            }
            printf("B%s\n", b64_final_answer);
            free(b64_final_answer);
            return 0;
            
        }else if (memcmp(decoded_challenge, "A",1) == 0){            
            fprintf(stderr,"Challenge type A not supported \n");
            return 1;
        }

    }else{
        print_usage(argv[0]);
        return 0;
    }   
    return 0;
}