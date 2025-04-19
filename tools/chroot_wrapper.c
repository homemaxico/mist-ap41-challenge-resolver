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
#include <libgen.h>  // For basename()

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

void print_usage(const char *program_name) {
    fprintf(stderr, "Usage: %s [-c chroot_dir] [-p program_name] [args...]\n", program_name);
    fprintf(stderr, "  -c chroot_dir    Specify the chroot directory (required)\n");
    fprintf(stderr, "  -p program_name  Specify the ARM binary to execute (if not provided, uses this program's name)\n");
    fprintf(stderr, "  All other arguments are passed to the ARM binary\n");
}

int main(int argc, char *argv[]) {
    char *chroot_dir = NULL;
    char *arm_binary = NULL;
    int opt;
    
    // Parse command line options
    while ((opt = getopt(argc, argv, "c:p:h")) != -1) {
        switch (opt) {
            case 'c':
                chroot_dir = optarg;
                break;
            case 'p':
                arm_binary = optarg;
                break;
            case 'h':
                print_usage(argv[0]);
                return 0;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }
    
    // Check if chroot directory was specified
    if (chroot_dir == NULL) {
        fprintf(stderr, "Error: Chroot directory (-c) is required\n");
        print_usage(argv[0]);
        return 1;
    }
    
    // If no ARM binary was specified, use this program's name
    if (arm_binary == NULL) {
        char *prog_copy = strdup(argv[0]);
        if (prog_copy == NULL) {
            perror("Failed to allocate memory");
            return 1;
        }
        arm_binary = basename(prog_copy);
        // We don't free prog_copy because arm_binary points to it
    }
    
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
        
        // Mount proc filesystem, try to unmount first just in case  anyway
        umount("/proc");
        if (mount("proc", "/proc", "proc", 0, NULL) != 0) {
            perror("Failed to mount /proc");
            exit(1);
        }
        
        // Prepare arguments for execv
        // We need: qemu-arm-static, binary path and remaining arguments
        // Count how many args we have left after option processing
        int remaining_args = argc - optind;
        char **new_args = malloc((remaining_args + 3) * sizeof(char *));
        if (!new_args) {
            perror("malloc failed");
            
            // Try to unmount /proc before exiting
            umount("/proc");
            exit(1);
        }
        
        // Fill in the arguments
        new_args[0] = "/usr/bin/qemu-arm-static";  // Path to qemu-arm-static
        new_args[1] = full_binary_path;           // Full path to ARM binary with /bin/ prefix
        
        // Copy additional arguments that were not processed as options
        for (int i = 0; i < remaining_args; i++) {
            new_args[i + 2] = argv[optind + i];
        }
        new_args[remaining_args + 2] = NULL;  // NULL-terminate the array
        
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
