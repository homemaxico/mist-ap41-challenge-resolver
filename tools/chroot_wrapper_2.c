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
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <chroot-dir> <arm-binary> [args...]\n", argv[0]);
        return 1;
    }

    const char *chroot_dir = argv[1];
    const char *arm_binary = argv[2];
    
    // Check if we're running as root
    if (geteuid() != 0) {
        printf("This program requires root privileges to use chroot.\n");
        
        // Ask for sudo password
        char password[256];
        get_password(password, sizeof(password));
        
        // Write password to a temporary file
        char temp_file[] = "/tmp/arm_debug_pwd_XXXXXX";
        int fd = mkstemp(temp_file);
        if (fd == -1) {
            perror("Failed to create temporary file");
            return 1;
        }
        
        write(fd, password, strlen(password));
        close(fd);
        
        // Set restrictive permissions on the file
        chmod(temp_file, 0600);
        
        // Build a command that will run this program with sudo
        char sudo_cmd[8192] = {0};
        
        // Use -A to read the password from a file (SUDO_ASKPASS)
        snprintf(sudo_cmd, sizeof(sudo_cmd), 
                "SUDO_ASKPASS=%s sudo -A ", 
                temp_file);
        
        // Append the current program and all its args, properly escaped
        strcat(sudo_cmd, argv[0]);
        for (int i = 1; i < argc; i++) {
            strcat(sudo_cmd, " '");
            strcat(sudo_cmd, argv[i]);
            strcat(sudo_cmd, "'");
        }
        
        // Append command to remove temp file at the end
        strcat(sudo_cmd, "; rm -f ");
        strcat(sudo_cmd, temp_file);
        
        // Replace ourself with a bash process that will execute the command
        // This preserves STDIN for the ultimate program
        execlp("bash", "bash", "-c", sudo_cmd, NULL);
        
        // If we get here, execlp failed
        perror("execlp failed");
        unlink(temp_file); // Clean up temp file
        return 1;
    }
    
    // If we get here, we're running as root
    
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
    
    // Fork a child process
    pid_t pid = fork();
    
    if (pid == -1) {
        perror("fork failed");
        return 1;
    }
    
    if (pid == 0) {
        // Child process
        
        // Change root directory
        if (chroot(chroot_dir) != 0) {
            perror("chroot failed");
            exit(1);
        }
        
        // Change directory to root of new filesystem
        if (chdir("/") != 0) {
            perror("chdir failed");
            exit(1);
        }
        
        // Mount proc filesystem
        if (mount("proc", "/proc", "proc", 0, NULL) != 0) {
            perror("Failed to mount /proc");
            exit(1);
        }
        
        // Prepare arguments for execv
        // We need: qemu-arm-static, binary path and all remaining arguments
        char **new_args = malloc((argc + 1) * sizeof(char *));
        if (!new_args) {
            perror("malloc failed");
            
            // Try to unmount /proc before exiting
            umount("/proc");
            exit(1);
        }
        
        new_args[0] = "/usr/bin/qemu-arm-static";  // Path to qemu-arm-static
        new_args[1] = full_binary_path;  // Full path to ARM binary with /bin/ prefix
        
        // Copy additional arguments
        for (int i = 3; i < argc; i++) {
            new_args[i-1] = argv[i];
        }
        new_args[argc-1] = NULL;  // NULL-terminate the array
        
        // Execute the command
        execv("/usr/bin/qemu-arm-static", new_args);
        
        // If we get here, execv failed
        perror("execv failed");
        free(new_args);
        
        // Try to unmount /proc before exiting
        umount("/proc");
        exit(1);
    } else {
        // Parent process
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