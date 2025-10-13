# The Complete Guide to prctl() - Process Control in Linux

**Author:** c0d3Ninja  
**Date:** October 2025  
**Version:** 1.0

---

## Table of Contents

1. [Introduction](#introduction)
2. [What is prctl()?](#what-is-prctl)
3. [Function Signature](#function-signature)
4. [Common Operations](#common-operations)
5. [Security & Stealth Applications](#security--stealth-applications)
6. [Practical Examples](#practical-examples)
7. [Detection Methods](#detection-methods)
8. [Advanced Techniques](#advanced-techniques)
9. [Best Practices](#best-practices)
10. [References](#references)

---

## Introduction

`prctl()` (process control) is a powerful Linux-specific system call that allows fine-grained control over various aspects of a process's behavior. Unlike traditional POSIX process management functions, `prctl()` provides access to Linux-specific features that are essential for security hardening, debugging, and yes—offensive security operations.

### Why prctl() Matters

- **Low-level control**: Direct kernel-level process manipulation
- **Security features**: Process isolation, capability management
- **Stealth operations**: Process name masquerading
- **Debugging**: Core dump control, death signals
- **Containerization**: Used extensively by Docker, systemd

---

## What is prctl()?

`prctl()` stands for "**PR**ocess **CTL**" (Process Control). It was introduced in Linux kernel 2.1.57 and has been expanded significantly over the years.

### Key Characteristics

- **Linux-specific**: Not portable to BSD, macOS, or Windows
- **Versatile**: Single syscall, multiple operations
- **Kernel-level**: Direct interaction with kernel process structures
- **Privileged operations**: Some require root or specific capabilities

### Man Page Reference

```bash
man 2 prctl
```

---

## Function Signature

```c
#include <sys/prctl.h>

int prctl(int option, unsigned long arg2, unsigned long arg3, 
          unsigned long arg4, unsigned long arg5);
```

### Parameters

| Parameter | Description |
|-----------|-------------|
| `option` | The operation to perform (e.g., `PR_SET_NAME`) |
| `arg2-5` | Operation-specific arguments |

### Return Value

- **Success**: Usually 0, sometimes operation-specific value
- **Error**: -1, with `errno` set appropriately

### Common Error Codes

- `EINVAL`: Invalid operation or argument
- `EPERM`: Permission denied (requires privileges)
- `EFAULT`: Invalid memory address

---

## Common Operations

### 1. PR_SET_NAME - Change Process Name

**Purpose:** Changes the name of the calling thread.

```c
prctl(PR_SET_NAME, "new_name", 0, 0, 0);
```

**Details:**
- Maximum 16 bytes (15 characters + null terminator)
- Shows in `/proc/PID/comm`
- Visible in `ps`, `top`, `htop`

**Example:**
```c
#include <sys/prctl.h>
#include <stdio.h>

int main() {
    if (prctl(PR_SET_NAME, "webserver", 0, 0, 0) == -1) {
        perror("prctl");
        return 1;
    }
    printf("Process name changed to 'webserver'\n");
    
    // Verify
    char name[16];
    prctl(PR_GET_NAME, name, 0, 0, 0);
    printf("Current name: %s\n", name);
    
    while(1); // Keep running
    return 0;
}
```

---

### 2. PR_GET_NAME - Get Process Name

**Purpose:** Retrieves the current process name.

```c
char name[16];
prctl(PR_GET_NAME, name, 0, 0, 0);
printf("Process name: %s\n", name);
```

---

### 3. PR_SET_DUMPABLE - Control Core Dumps

**Purpose:** Enable or disable core dump generation.

```c
// Disable core dumps
prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);

// Enable core dumps
prctl(PR_SET_DUMPABLE, 1, 0, 0, 0);

// Check current state
int dumpable = prctl(PR_GET_DUMPABLE, 0, 0, 0, 0);
```

**Use Cases:**
- **Security**: Prevent sensitive data in crash dumps
- **Anti-debugging**: Harder to attach debuggers
- **Compliance**: Avoid leaking credentials in dumps

**States:**
- `0`: Not dumpable
- `1`: Dumpable (default)
- `2`: Dumpable (only readable by root)

---

### 4. PR_SET_PDEATHSIG - Parent Death Signal

**Purpose:** Set signal to receive when parent process dies.

```c
#include <signal.h>

// Kill child when parent dies
prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0);
```

**Use Cases:**
- **Cleanup**: Ensure children don't become orphans
- **Security**: Kill backdoor if parent is terminated
- **Resource management**: Prevent zombie processes

**Example:**
```c
#include <sys/prctl.h>
#include <signal.h>
#include <unistd.h>
#include <stdio.h>

int main() {
    pid_t pid = fork();
    
    if (pid == 0) {
        // Child process
        prctl(PR_SET_PDEATHSIG, SIGTERM);
        printf("Child: Will receive SIGTERM if parent dies\n");
        
        while(1) {
            printf("Child alive...\n");
            sleep(2);
        }
    } else {
        // Parent process
        printf("Parent: Sleeping for 5 seconds then exiting\n");
        sleep(5);
        printf("Parent: Exiting (child should die too)\n");
    }
    
    return 0;
}
```

---

### 5. PR_SET_NO_NEW_PRIVS - Prevent Privilege Escalation

**Purpose:** Disable gaining new privileges via `execve()`.

```c
prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
```

**Effects:**
- Cannot execute setuid/setgid binaries
- Cannot gain capabilities
- **Cannot be reversed** (permanent)

**Use Cases:**
- **Sandboxing**: Browser processes, containers
- **Security**: Reduce attack surface
- **Least privilege**: Enforce principle

---

### 6. PR_SET_SECCOMP - Security Computing Mode

**Purpose:** Restrict system calls available to the process.

```c
#include <linux/seccomp.h>

// Strict mode - only read, write, exit, sigreturn
prctl(PR_SET_SECCOMP, SECCOMP_MODE_STRICT, 0, 0, 0);
```

**Modes:**
- `SECCOMP_MODE_STRICT`: Only 4 syscalls allowed
- `SECCOMP_MODE_FILTER`: Custom BPF filter

**Use Cases:**
- **Sandboxing**: Chrome, Firefox, Docker
- **Zero trust**: Minimal syscall exposure
- **Exploit mitigation**: Reduce attack surface

---

### 7. PR_CAPBSET_DROP - Drop Capability

**Purpose:** Remove capabilities from the bounding set.

```c
#include <linux/capability.h>

// Drop ability to bind to privileged ports
prctl(PR_CAPBSET_DROP, CAP_NET_BIND_SERVICE, 0, 0, 0);
```

**Use Cases:**
- **Privilege separation**: Drop unneeded capabilities
- **Security hardening**: Minimize attack surface

---

## Security & Stealth Applications

### Process Masquerading

**Technique:** Change process name to mimic legitimate system processes.

```c
#include <sys/prctl.h>

void hide_as_kernel_thread() {
    // Mimic kernel worker thread
    prctl(PR_SET_NAME, "[kworker/u8:2]", 0, 0, 0);
}

void hide_as_system_daemon() {
    // Mimic systemd journal
    prctl(PR_SET_NAME, "systemd-journal", 0, 0, 0);
}
```

**Common Masquerade Names:**

| Legitimate Process | Description | Suspicion Level |
|-------------------|-------------|-----------------|
| `[kworker/0:1]` | Kernel worker thread | Very Low |
| `[migration/0]` | Kernel migration thread | Very Low |
| `systemd-journal` | System logging daemon | Low |
| `accounts-daemon` | User account service | Low |
| `dbus-daemon` | Message bus daemon | Medium |

**Detection:**
```bash
# Find mismatched names vs binary
for pid in /proc/[0-9]*; do
  name=$(cat $pid/comm 2>/dev/null)
  exe=$(readlink $pid/exe 2>/dev/null)
  [ -n "$exe" ] && [ "$(basename $exe)" != "$name" ] && \
    echo "Suspicious: PID=$(basename $pid) NAME=$name EXE=$exe"
done
```

---

### Anti-Debugging

**Technique:** Prevent debuggers and core dumps.

```c
void anti_debug() {
    // Disable core dumps
    prctl(PR_SET_DUMPABLE, 0);
    
    // Check if being traced
    if (prctl(PR_SET_DUMPABLE, 0) == -1) {
        // Already being debugged
        exit(1);
    }
}
```

**Advanced Anti-Debug:**
```c
#include <sys/ptrace.h>

int is_debugged() {
    // Try to trace ourselves
    if (ptrace(PTRACE_TRACEME, 0, 1, 0) == -1) {
        return 1; // Already being traced
    }
    ptrace(PTRACE_DETACH, 0, 1, 0);
    
    // Check TracerPid in /proc/self/status
    FILE *f = fopen("/proc/self/status", "r");
    char line[256];
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "TracerPid:", 10) == 0) {
            int pid;
            sscanf(line, "TracerPid: %d", &pid);
            fclose(f);
            return (pid != 0);
        }
    }
    fclose(f);
    return 0;
}
```

---

### Persistent Backdoors

**Technique:** Ensure backdoor cleanup when parent is killed.

```c
void setup_backdoor() {
    pid_t pid = fork();
    
    if (pid == 0) {
        // Child - backdoor process
        
        // Kill self if parent dies
        prctl(PR_SET_PDEATHSIG, SIGKILL);
        
        // Hide process name
        prctl(PR_SET_NAME, "[kworker/0:1]");
        
        // Disable core dumps
        prctl(PR_SET_DUMPABLE, 0);
        
        // Your backdoor code here
        while(1) {
            // Reverse shell logic
            sleep(300); // Try every 5 minutes
        }
    } else {
        // Parent exits immediately
        exit(0);
    }
}
```

---

## Practical Examples

### Example 1: Multi-threaded Process with Named Threads

```c
#include <pthread.h>
#include <sys/prctl.h>
#include <stdio.h>
#include <unistd.h>

void* worker_thread(void* arg) {
    const char* name = (const char*)arg;
    
    // Name this thread
    prctl(PR_SET_NAME, name);
    
    printf("Thread %s started\n", name);
    
    while(1) {
        // Work...
        sleep(5);
    }
    
    return NULL;
}

int main() {
    pthread_t threads[3];
    
    pthread_create(&threads[0], NULL, worker_thread, "db-worker");
    pthread_create(&threads[1], NULL, worker_thread, "net-worker");
    pthread_create(&threads[2], NULL, worker_thread, "io-worker");
    
    // Keep main thread alive
    pthread_join(threads[0], NULL);
    
    return 0;
}
```

**Viewing threads:**
```bash
ps -eLf | grep your_program
# Shows individual thread names
```

---

### Example 2: Secure Daemon

```c
#include <sys/prctl.h>
#include <unistd.h>
#include <signal.h>

void create_secure_daemon() {
    // Fork twice (double fork pattern)
    pid_t pid = fork();
    if (pid > 0) exit(0);
    
    setsid(); // New session
    
    pid = fork();
    if (pid > 0) exit(0);
    
    // Now we're a daemon
    
    // Security hardening
    prctl(PR_SET_DUMPABLE, 0);           // No core dumps
    prctl(PR_SET_NO_NEW_PRIVS, 1);       // Can't escalate
    prctl(PR_SET_NAME, "secure-daemon"); // Set name
    
    chdir("/");
    umask(0);
    
    // Close file descriptors
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);
    
    // Your daemon logic here
    while(1) {
        sleep(60);
    }
}
```

---

### Example 3: Sandboxed Child Process

```c
#include <sys/prctl.h>
#include <linux/seccomp.h>
#include <linux/filter.h>

void run_sandboxed_code() {
    pid_t pid = fork();
    
    if (pid == 0) {
        // Child - sandboxed
        
        // 1. No new privileges
        prctl(PR_SET_NO_NEW_PRIVS, 1);
        
        // 2. Kill if parent dies
        prctl(PR_SET_PDEATHSIG, SIGKILL);
        
        // 3. Name the process
        prctl(PR_SET_NAME, "sandbox");
        
        // 4. Enable seccomp (simplified)
        prctl(PR_SET_SECCOMP, SECCOMP_MODE_STRICT);
        
        // Only read, write, exit, sigreturn available now
        
        // Your untrusted code here
        // ...
        
        _exit(0);
    } else {
        // Parent waits
        waitpid(pid, NULL, 0);
    }
}
```

---

## Detection Methods

### Blue Team: Finding Hidden Processes

**Script 1: Compare COMM vs Binary Name**
```bash
#!/bin/bash
# detect_masquerading.sh

echo "Checking for process name mismatches..."

for pid_dir in /proc/[0-9]*; do
    pid=$(basename "$pid_dir")
    
    # Skip if not accessible
    [ -r "$pid_dir/comm" ] || continue
    
    comm=$(cat "$pid_dir/comm" 2>/dev/null)
    exe=$(readlink "$pid_dir/exe" 2>/dev/null)
    
    if [ -n "$exe" ]; then
        exe_name=$(basename "$exe")
        
        # Check if names match
        if [ "$comm" != "$exe_name" ]; then
            echo "SUSPICIOUS: PID=$pid COMM='$comm' EXE='$exe'"
        fi
    fi
done
```

**Script 2: Find Fake Kernel Threads**
```bash
#!/bin/bash
# detect_fake_kthreads.sh

# Real kernel threads have no /proc/PID/exe symlink
# Fake ones do

for pid_dir in /proc/[0-9]*; do
    pid=$(basename "$pid_dir")
    comm=$(cat "$pid_dir/comm" 2>/dev/null)
    
    # Check if name looks like kernel thread
    if [[ "$comm" =~ ^\[.*\]$ ]]; then
        # But has an exe (userspace program)
        if [ -e "$pid_dir/exe" ]; then
            exe=$(readlink "$pid_dir/exe" 2>/dev/null)
            echo "FAKE KERNEL THREAD: PID=$pid COMM='$comm' EXE='$exe'"
        fi
    fi
done
```

---

## Advanced Techniques

### Combining prctl() with argv[0] Manipulation

For maximum stealth, change both COMM and command line:

```c
#include <sys/prctl.h>
#include <string.h>

void full_masquerade(int argc, char* argv[]) {
    const char* fake_name = "[kworker/u16:2]";
    
    // Change kernel's view (COMM)
    prctl(PR_SET_NAME, fake_name);
    
    // Change command line (argv[0])
    if (argc > 0 && argv[0]) {
        size_t max_len = strlen(argv[0]);
        memset(argv[0], 0, max_len);
        strncpy(argv[0], fake_name, max_len - 1);
    }
}
```

**Result:**
```bash
# ps aux shows:
USER  PID  COMM           CMD
root  123  [kworker/u16:2]  [kworker/u16:2]
```

---

### Thread-Specific Operations

Each thread can have its own name:

```c
#include <pthread.h>

void* thread_func(void* arg) {
    // Each thread gets unique name
    pthread_setname_np(pthread_self(), "my-thread");
    
    // Or use prctl
    prctl(PR_SET_NAME, "worker-1");
    
    // Work...
    return NULL;
}
```

---

## Best Practices

### Defensive Programming

```c
int safe_prctl_set_name(const char* name) {
    if (!name || strlen(name) >= 16) {
        return -1;
    }
    
    if (prctl(PR_SET_NAME, name, 0, 0, 0) == -1) {
        perror("prctl(PR_SET_NAME)");
        return -1;
    }
    
    return 0;
}
```

### Security Hardening Checklist

```c
void harden_process() {
    // 1. Disable core dumps
    prctl(PR_SET_DUMPABLE, 0);
    
    // 2. Prevent privilege escalation
    prctl(PR_SET_NO_NEW_PRIVS, 1);
    
    // 3. Kill children when parent dies
    prctl(PR_SET_PDEATHSIG, SIGKILL);
    
    // 4. Set appropriate name
    prctl(PR_SET_NAME, "secure-app");
    
    // 5. Drop capabilities (if running as root)
    // prctl(PR_CAPBSET_DROP, CAP_SYS_ADMIN);
}
```

---

## References

### Official Documentation
- Linux man page: `man 2 prctl`
- Kernel source: `include/uapi/linux/prctl.h`
- Linux kernel docs: https://www.kernel.org/doc/Documentation/

### Security Research
- MITRE ATT&CK: T1036.004 (Masquerade Task or Service)
- MITRE ATT&CK: T1564 (Hide Artifacts)

### Books
- "The Linux Programming Interface" by Michael Kerrisk
- "Linux Kernel Development" by Robert Love

### Online Resources
- https://man7.org/linux/man-pages/man2/prctl.2.html
- https://lwn.net/Articles/475678/ (Seccomp)
- https://www.kernel.org/doc/html/latest/

---

## Conclusion

`prctl()` is a powerful, multi-purpose system call that provides fine-grained control over Linux processes. While it has legitimate uses in security hardening, containerization, and system programming, it's also a favorite tool for malware authors and red teams.

Understanding `prctl()` is essential for:
- **Developers**: Building secure, well-behaved applications
- **Security engineers**: Hardening systems and detecting threats
- **Penetration testers**: Evading detection and maintaining access
- **Malware analysts**: Understanding advanced evasion techniques

### Key Takeaways

1. **PR_SET_NAME** is limited to 15 characters
2. **Most operations cannot be reversed** (especially security-related ones)
3. **Not all prctl() operations are available on all kernels**
4. **Process masquerading is easily detected** with proper monitoring
5. **Combine multiple techniques** for better evasion

---

**Disclaimer:** This guide is for educational and authorized security testing purposes only. Unauthorized access to computer systems is illegal. Always obtain proper authorization before testing security techniques.

---

**Created for:** ShadowHarvester v1.0  
**Author:** c0d3Ninja  
**License:** Educational Use

