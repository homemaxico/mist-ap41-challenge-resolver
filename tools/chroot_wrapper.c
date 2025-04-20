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
        char *arm_binary, size_t arm_binary_size) {
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
                    printf("found!\n");
                
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

int fork_chroot(char* command_args, char* chroot_dir, char* full_binary_path){

    
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
        char *new_args = calloc(7, sizeof(char*));
        

        strcat(new_args, "sshpass -P \"[sudo]\" sudo chroot ");          
        strcat(new_args, chroot_dir);
        strcat(new_args, " /bin/stty echo&& ");
        strcat(new_args, "sudo chroot  ");
        strcat(new_args, chroot_dir);
        strcat(new_args, " /usr/bin/qemu-arm-static ");
        strcat(new_args, full_binary_path);
        strcat(new_args, " ");
        strcat(new_args, command_args);
        
        
        execlp("bash", "bash", "-x", "-c", new_args, NULL);
        
        // If we get here, execv failed
        
        perror("execv failed");
        free(new_args);

        // Try to unmount /proc before exiting
        //umount("/proc");
        exit(1);
    } else {
        // Parent process, the child has stopped
        int status;
        waitpid(pid, &status, 0);

        // Try to unmount /proc from outside the chroot
        char parent_proc_path[2048];
        snprintf(parent_proc_path, sizeof(parent_proc_path), "%s/proc", chroot_dir);
        umount(parent_proc_path); // Ignore errors as the child might have already unmounted it

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
    const char *chroot_dir = NULL;
    const char *arm_binary = NULL;
    char config_chroot_dir[1024] = {0};
    char config_arm_binary[1024] = {0};
    
    // Get the binary name from argv[0]
    char *binary_name = basename(argv[0]);
    int has_config = 0;
    
    // Check if we have a configuration for this binary
    if (check_config_files(binary_name, config_chroot_dir, sizeof(config_chroot_dir),
                          config_arm_binary, sizeof(config_arm_binary)) == 1) {
        chroot_dir = config_chroot_dir;
        arm_binary = config_arm_binary;
        has_config = 1;
        printf("chroot_dir: %s\n", chroot_dir);
        printf("arm_binary: %s\n", arm_binary);
        printf("Has_config: %d\n", has_config);

    }else{ 
        // No config found, check command line arguments
        
        if ( (&has_config == 0) && (argc < 3) ) {
            fprintf(stderr, "Usage: %s <chroot-dir> <arm-binary> [args...]\n", argv[0]);
            for (int i = 1; i < argc; i++) {
                printf("argv[%d]: %s\n", i, argv[i]);
                printf("has_config: %d\n", has_config);
            
            }
            return 1;
        }
    }
    
    if (has_config == 0){ 
        chroot_dir = argv[1];
        arm_binary = argv[2];
    }
    
    // Check if we're running as root
    if (geteuid() != 0) {
        printf("This program requires root privileges to use chroot.\n");
        
        
        // Build a command that will run this program with sudo
        char arm_args[8192] = {0};

       // Create full path with /bin/ prefix
       char full_binary_path[1024];
       snprintf(full_binary_path, sizeof(full_binary_path), "/bin/%s", arm_binary);
        
       // Create directory for /proc in chroot if it doesn't exist
       char proc_dir[2048];
       snprintf(proc_dir, sizeof(proc_dir), "%s/proc", chroot_dir);
        
       struct stat st = {0};
       if (stat(proc_dir, &st) == -1) {
           // /proc doesn't exist in chroot, create it
           if (mkdir(proc_dir, 0755) == -1) {
               perror("Failed to create /proc directory in chroot");
               return 1;
           }
       }
       // Check if /proc is mounted
       strcat(proc_dir,"/cmdline");
       if (stat(proc_dir, &st) == -1) {
           // Try to mount proc filesystem
           if (mount("proc", "/proc", "proc", 0, NULL) != 0) {
               perror("Failed to mount /proc");
               exit(1);
           }
       }

        
        // Append the current program and all its args, properly escaped
        //strcat(arm_args, argv[0]);
        
        for (int i = 1; i < argc; i++) { // this will only work for not setuid=0, fix
            strcat(arm_args, " '");
            strcat(arm_args, argv[i]);
            strcat(arm_args, "'");
        }

    
        disable_echo();
        fork_chroot(arm_args,(char*)chroot_dir,full_binary_path);      
        
        

        
        // If we get here, execlp failed
        perror("execlp failed");
        return 1;
    }
    
}
    
    
    