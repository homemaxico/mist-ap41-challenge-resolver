#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <termios.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>

/* 
* This program is a wrapper for gdb. When called it changes the -ex options on the fly for a gdb session.
*/

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

int main(int argc, char *argv[]) {
    // Check if we're running as root
    if (geteuid() != 0) {
        printf("GDB often requires root privileges for debugging.\n");
   
        // Ask for sudo password
        char password[256];
        get_password(password, sizeof(password));
        
        // Write password to a temporary file
        char temp_file[] = "/tmp/gdb_sudo_pwd_XXXXXX";
        int fd = mkstemp(temp_file);
        if (fd == -1) {
            perror("Failed to create temporary file");
            return 1;
        }
        
        write(fd, password, strlen(password));
        close(fd);
        
        // Set restrictive permissions on the file
        chmod(temp_file, 0600);
        
        // Create a shell script that will be used as SUDO_ASKPASS
        char askpass_file[] = "/tmp/gdb_askpass_XXXXXX";
        int askpass_fd = mkstemp(askpass_file);
        if (askpass_fd == -1) {
            perror("Failed to create askpass script");
            unlink(temp_file);
            return 1;
        }
        
        // Write a simple shell script that outputs the password
        char askpass_script[1024];
        snprintf(askpass_script, sizeof(askpass_script), 
                 "#!/bin/sh\ncat %s\n", temp_file);
        write(askpass_fd, askpass_script, strlen(askpass_script));
        close(askpass_fd);
        
        // Make the askpass script executable
        chmod(askpass_file, 0700);
        
        // Build a command that will run gdb withsudo_cmd sudo
        char sudo_cmd[8192] = {0};
        
        // Use -A to read the password from the askpass script
        snprintf(sudo_cmd, sizeof(sudo_cmd), 
                "SUDO_ASKPASS=%s sudo -A gdb", 
                askpass_file);
        
        // Append all GDB arguments, properly escaped

        char *arm_bin = (char*)malloc(256);
        char *chroot_path = (char*)malloc(256);
        char *set_args = (char*)malloc(256);
        char *full_arm_path = (char*)malloc(256);

        for (int i = 1; i < argc; i++) {

            if ( memcmp(argv[i],"file",4) == 0){
                strcat(sudo_cmd," ");
                arm_bin = basename(argv[i+1]);
                memcpy(chroot_path, argv[i+1], (strlen(argv[i+1]) - strlen(arm_bin) - strlen("/bin/") ));                
                argv[i] = "file /usr/sbin/chroot";
                argv[i+1] = "";
                strcat(sudo_cmd, "'");
                strcat(sudo_cmd,argv[i]);
                strcat(sudo_cmd, "'");

            }else        
            if ( memcmp(argv[i],"set args ",9)==0){
                strcat(sudo_cmd," ");
                strcat(sudo_cmd, "'");
                int len_args = (strlen(argv[i]) - strlen("set args "));
                strcat(sudo_cmd, "set args ");
                strcat(sudo_cmd, chroot_path);
                strcat(sudo_cmd, " qemu-arm-static /bin/");
                strcat(sudo_cmd, arm_bin);
                strcat(sudo_cmd," ");
                memcpy(sudo_cmd+(strlen(sudo_cmd)), argv[i]+strlen("set args "),len_args+strlen("/bin/"));
                strcat(sudo_cmd, "'");

            }else
            if (argv[i]!=""){
                strcat(sudo_cmd, " ");            
                strcat(sudo_cmd, "'");
                strcat(sudo_cmd,argv[i]);
                strcat(sudo_cmd, "'");
            }
            
        }
        
        
        // Append commands to remove temp files at the end
        strcat(sudo_cmd, "; rm -f ");

        strcat(sudo_cmd, temp_file);
        strcat(sudo_cmd, " ");
        strcat(sudo_cmd, askpass_file);
        
        // Replace ourself with a bash process that will execute the command
        // This preserves STDIN for GDB
        execlp("bash", "bash", "-c", sudo_cmd, NULL);
        // If we get here, execlp failed
        perror("execlp failed");
        unlink(temp_file);
        unlink(askpass_file);
        return 1;
    } else {
        // We're already running as root, just exec gdb directly
        char **gdb_args = malloc((argc + 1) * sizeof(char *));
        if (!gdb_args) {
            perror("malloc failed");
            return 1;
        }
        
        gdb_args[0] = "gdb";
        
        // Copy all arguments to gdb
        char *arm_bin = (char*)malloc(256);
        char *chroot_path = (char*)malloc(256);
        char *set_args = (char*)malloc(256);
        char *full_arm_path = (char*)malloc(256);

        
        for (int i = 1; i < argc; i++) {
            if ( memcmp(argv[i],"file",4) == 0){
                printf("file: %s\n", argv[i+1]);  
                arm_bin = basename(argv[i+1]);
                memcpy(chroot_path,argv[i+1], (strlen(argv[i+1]) - strlen(arm_bin) - strlen("/bin/") ));
                argv[i] = "file /usr/sbin/chroot";                
                argv[i+1] = " ";
                printf("file2: %s\n", argv[i+1]); 
            }         
            if ( memcmp(argv[i],"set args",8)==0){
                int len_args = (strlen(argv[i]) - strlen("set args "));
                strcat(set_args, "set args ");
                strcat(set_args, chroot_path);
                strcat(set_args, " qemu-arm-static /bin/");
                strcat(set_args, arm_bin);
                strcat(set_args," ");
                memcpy(set_args+(strlen(set_args)), argv[i]+strlen("set args "),len_args+strlen("/bin/"));

                argv[i] = set_args;
                printf("set args: %s\n", argv[i]);

            }
            gdb_args[i] = argv[i];
            //printf("file: %s\n", argv[i]);

        }
        gdb_args[argc] = NULL;  // NULL-terminate the array
        
        // Execute gdb
        execvp("gdb", gdb_args);
        
        // If we get here, execvp failed
        perror("execvp failed");
        free(gdb_args);
        return 1;
    }
    
    return 0;
}
