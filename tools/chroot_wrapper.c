#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <termios.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>


// Function to disable terminal echo for password input
void disable_echo() {
    struct termios term;
    tcgetattr(STDIN_FILENO, &term);
    term.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &term);
}

// Function to enable terminal echo
void enable_echo() {
    struct termios term;
    tcgetattr(STDIN_FILENO, &term);
    term.c_lflag |= ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &term);
}

// Function to get password from user
void get_password(char *password, size_t size) {
    printf("Enter sudo password: ");
    fflush(stdout);
    
    disable_echo();
    if (fgets(password, size, stdin) == NULL) {
        password[0] = '\0';
    } else {
        // Remove newline character
        size_t len = strlen(password);
        if (len > 0 && password[len-1] == '\n') {
            password[len-1] = '\0';
        }
    }
    enable_echo();
    printf("\n");
}

// Function to check config files for binary settings
// Returns 1 if found, 0 if not found
int check_config_files(const char *binary_name, char *chroot_dir, size_t chroot_dir_size, 
        char *arm_binary) {
    FILE *config_file = NULL;
    char line[1024];
    char config_path[1024];
    const char *home_dir = getenv("HOME");

    // Try home directory first
    if (home_dir) {
        snprintf(config_path, sizeof(config_path), "%s/.arm_chroot_wrapper", home_dir);
        config_file = fopen(config_path, "r");
    }

    // If not found in home directory, try /etc
    if (!config_file) {
        config_file = fopen("/etc/arm_chroot_wrapper.conf", "r");
    }

    // If still not found, return failure
        if (!config_file) {
    return 0;
    }

    // Search for binary_name in the config file
    while (fgets(line, sizeof(line), config_file)) {
        // Remove newline character if present
        size_t len = strlen(line);
        if (len > 0 && line[len-1] == '\n') {
        line[len-1] = '\0';
        len--;
    }

    // Skip empty lines and comments
    if (len == 0 || line[0] == '#') {
        continue;
    }

    // Check for binary_name match
    const char *colon = strchr(line, ':');
        if (colon) {
            size_t first_field_len = colon - line;
        
            if (strncmp(binary_name, line, first_field_len) == 0 && 
                binary_name[first_field_len] == '\0') {
                
                // Found a match, extract fields
                const char *second_field = colon + 1;
                
                // Copy first field (binary name) to arm_binary
                strncpy(arm_binary, line, first_field_len);
                arm_binary[first_field_len] = '\0';
                
                // Copy second field (chroot dir) to chroot_dir
                strncpy(chroot_dir, second_field, chroot_dir_size - 1);
                chroot_dir[chroot_dir_size - 1] = '\0';
                
                fclose(config_file);
                return 1;
            }
        }
    }

    fclose(config_file);
    return 0;
}

struct chroot_wrap {
    char *binary_name2;
    char *binary_args2;
    char *chroot_dir2;
    char *qemu_cmd;
    uint8_t has_config;
    uint8_t proc_is_there;
    uint8_t proc_is_mounted;
}chroot_wrap;


int fork_chroot(struct chroot_wrap* st){

    
    // Fork a child process
    pid_t pid = fork();

    if (pid == -1) {
        perror("fork failed");
        return 1;
    }

    if (pid == 0) {
        // Child process

        // Prepare arguments for execv
        // We need: qemu-arm-static, binary path and all remaining arguments
        char *new_args2 = malloc(80);

        if (new_args2 == NULL) {
            return 1;
        }
        new_args2[0] ='\0';


        strcpy(new_args2, "sshpass -P \"[sudo]\" sudo chroot ");
        strcat(new_args2, st->chroot_dir2);
        strcat(new_args2, " ");
        strcat(new_args2, st->qemu_cmd);
        strcat(new_args2, " ");
        //Enable echo on sttdin and continue
        strcat(new_args2, "/bin/stty echo &&  sudo chroot ");
        strcat(new_args2, st->chroot_dir2);
        strcat(new_args2, " ");
        strcat(new_args2, st->qemu_cmd);
        strcat(new_args2, " ");

        if (st->proc_is_there == 0){            
            strcat(new_args2, "/bin/mkdir /proc &&  sudo chroot ");
            strcat(new_args2, st->chroot_dir2);
            strcat(new_args2, " ");
            strcat(new_args2, st->qemu_cmd);
            strcat(new_args2, " ");            
        }
        
        if (st->proc_is_mounted == 0){
            strcat(new_args2, "/bin/mount -t proc /proc/ && sudo  chroot ");
            strcat(new_args2, st->chroot_dir2);
            strcat(new_args2, " ");
            strcat(new_args2, st->qemu_cmd);
            strcat(new_args2, " ");
        }
        
        //Final sudo execution of chroot
        strcat(new_args2, st->binary_name2);
        strcat(new_args2, " ");
        strcat(new_args2, st->binary_args2);

        //Only try to unmount /proc if we mounted in the first place
        if (st->proc_is_mounted == 1){
            strcat(new_args2, "&& echo 'Warning: Sudo password may be required again!' && sudo  ");
            strcat(new_args2, st->chroot_dir2);
            strcat(new_args2, " ");
            strcat(new_args2, st->qemu_cmd);
            strcat(new_args2, " ");
            strcat(new_args2, "/bin/umount /proc");
        }

                
        execlp("bash", "bash", "-x", "-c", new_args2, NULL);
        free(st);
        
        // If we get here, execv failed        
        free(new_args2);
        perror("execv failed");

        exit(1);
    } else {
        // Parent process, the child has stopped
        int status;
        waitpid(pid, &status, 0);


        if (WIFEXITED(status)) {
            printf("Child exited with status %d\n", WEXITSTATUS(status));
            return WEXITSTATUS(status);
        } else if (WIFSIGNALED(status)) {
            printf("Child terminated by signal %d\n", WTERMSIG(status));
            return 1;
        }
    }

return 0;

}



int main(int argc, char *argv[]) {

    char config_chroot_dir[1024] = {0};
    char config_arm_binary[1024] = {0};

    struct chroot_wrap *chroot_st = malloc(sizeof(struct chroot_wrap));

    // Get the binary name from argv[0]
    char *binary_name = basename(argv[0]);
    chroot_st->has_config = 0;
    chroot_st->proc_is_there = 0;
    chroot_st->proc_is_mounted = 0;

    // Calculate required space: length of "/bin/" + length of binary2 + 1 for null terminator
    int path_len = strlen("/bin/") + strlen(binary_name) + 1;

    // Allocate memory for the full path
    chroot_st->binary_name2 = malloc(path_len);
    
    if (!chroot_st->binary_name2) {
        // Handle allocation failure
        return 1;
    }

    chroot_st->qemu_cmd = " /usr/bin/qemu-arm-static ";
        
    
    // Check if we have a configuration for this binary
    if (check_config_files(binary_name, config_chroot_dir, sizeof(config_chroot_dir),
                            config_arm_binary) == 1) {

        chroot_st->has_config = 1;

        sprintf(chroot_st->binary_name2, "/bin/%s", config_arm_binary);
        
        chroot_st->chroot_dir2 = config_chroot_dir;
        chroot_st->binary_args2 = argv[1]; //TODO FIX: This will probably only work for one arg but let's start somewehere 
        chroot_st->has_config = 1;
    
    }else{ 
        // No config found, check command line arguments
        
        if ( (chroot_st->has_config == 0) && (argc < 3) ) {
            fprintf(stderr, "Usage: %s <chroot-dir> <arm-binary> [args...]\n", argv[0]);
            return 1;
        }
    }
    
    if (chroot_st->has_config == 0){ 

        chroot_st->chroot_dir2 = argv[1];
        sprintf(chroot_st->binary_name2, "/bin/%s", argv[2]);

        chroot_st->binary_args2 = argv[3];

        //chroot_dir = argv[1];
        //arm_binary = argv[2];
    }
    
    // Check if we're running as root
    if (geteuid() != 0) {
        printf("This program requires root privileges to use chroot.\n");
        
        
        // Build a command that will run this program with sudo
        char arm_args[8192] = {0};

        
       // Create directory for /proc in chroot if it doesn't exist
       char proc_dir[2048];
       snprintf(proc_dir, sizeof(proc_dir), "%s/proc", chroot_st->chroot_dir2);
        
       struct stat st = {0};
       if (stat(proc_dir, &st) == -1) {
           // /proc doesn't exist in chroot, create it
           if (mkdir(proc_dir, 0755) == -1) {
               perror("Failed to create /proc directory in chroot");
               return 1;
           }
       }else{
        chroot_st->proc_is_there = 1;
       }
       // Check if /proc is mounted
       
       strcat(proc_dir,"/cmdline");
       
       if (stat(proc_dir, &st) != -1) {
        chroot_st->proc_is_mounted = 1;
       }

        // Append the current program and all its args, properly escaped
        //strcat(arm_args, argv[0]);
        
        for (int i = 1; i < argc; i++) { // this will only work for not setuid=0, fix
            strcat(arm_args, " '");
            strcat(arm_args, argv[i]);
            strcat(arm_args, "'");
        }

    
        disable_echo();
        fork_chroot(chroot_st);      
        
        

        
        // If we get here, execlp failed
        perror("execlp failed");
        return 1;
    }
    
}
    
    
    