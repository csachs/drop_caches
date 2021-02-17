// This is an auto-generated, largely untested experiment, do not use unless you understand it.
// Many syscall-calls are likely broken.

#include <stdint.h>

#if defined(__amd64__)

static inline uint64_t syscall0(uint64_t num) {
    uint64_t return_value;
    register uint64_t rax __asm__("rax") = num;
    asm volatile (
    "syscall"
    : "=a"(return_value)
    : "a"(rax)
    : "rcx", "r11", "memory");
    return return_value;
}

static inline uint64_t syscall1(uint64_t num, uint64_t arg1) {
    uint64_t return_value;
    register uint64_t rax __asm__("rax") = num;
    asm volatile (
    "syscall"
    : "=a"(return_value)
    : "a"(rax), "D"(arg1)
    : "rcx", "r11", "memory");
    return return_value;
}

static inline uint64_t syscall2(uint64_t num, uint64_t arg1, uint64_t arg2) {
    uint64_t return_value;
    register uint64_t rax __asm__("rax") = num;
    asm volatile (
    "syscall"
    : "=a"(return_value)
    : "a"(rax), "D"(arg1), "S"(arg2)
    : "rcx", "r11", "memory");
    return return_value;
}

static inline uint64_t syscall3(uint64_t num, uint64_t arg1, uint64_t arg2, uint64_t arg3) {
    uint64_t return_value;
    register uint64_t rax __asm__("rax") = num;
    asm volatile (
    "syscall"
    : "=a"(return_value)
    : "a"(rax), "D"(arg1), "S"(arg2), "d"(arg3)
    : "rcx", "r11", "memory");
    return return_value;
}

static inline uint64_t syscall4(uint64_t num, uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4) {
    uint64_t return_value;
    register uint64_t rax __asm__("rax") = num;
    register uint64_t r10 __asm__("r10") = (uint64_t)arg4;
    asm volatile (
    "syscall"
    : "=a"(return_value)
    : "a"(rax), "D"(arg1), "S"(arg2), "d"(arg3), "r"(r10)
    : "rcx", "r11", "memory");
    return return_value;
}

static inline uint64_t syscall5(uint64_t num, uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    uint64_t return_value;
    register uint64_t rax __asm__("rax") = num;
    register uint64_t r10 __asm__("r10") = (uint64_t)arg4;
    register uint64_t r8 __asm__("r8") = (uint64_t)arg5;
    asm volatile (
    "syscall"
    : "=a"(return_value)
    : "a"(rax), "D"(arg1), "S"(arg2), "d"(arg3), "r"(r10), "r"(r8)
    : "rcx", "r11", "memory");
    return return_value;
}

static inline uint64_t syscall6(uint64_t num, uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    uint64_t return_value;
    register uint64_t rax __asm__("rax") = num;
    register uint64_t r10 __asm__("r10") = (uint64_t)arg4;
    register uint64_t r8 __asm__("r8") = (uint64_t)arg5;
    register uint64_t r9 __asm__("r9") = (uint64_t)arg6;
    asm volatile (
    "syscall"
    : "=a"(return_value)
    : "a"(rax), "D"(arg1), "S"(arg2), "d"(arg3), "r"(r10), "r"(r8), "r"(r9)
    : "rcx", "r11", "memory");
    return return_value;
}

enum syscall { syscall_read = 0, syscall_write = 1, syscall_open = 2, syscall_close = 3, syscall_stat = 4, syscall_fstat = 5, syscall_lstat = 6, syscall_poll = 7, syscall_lseek = 8, syscall_mmap = 9, syscall_mprotect = 10, syscall_munmap = 11, syscall_brk = 12, syscall_rt_sigaction = 13, syscall_rt_sigprocmask = 14, syscall_rt_sigreturn = 15, syscall_ioctl = 16, syscall_pread64 = 17, syscall_pwrite64 = 18, syscall_readv = 19, syscall_writev = 20, syscall_access = 21, syscall_pipe = 22, syscall_select = 23, syscall_sched_yield = 24, syscall_mremap = 25, syscall_msync = 26, syscall_mincore = 27, syscall_madvise = 28, syscall_shmget = 29, syscall_shmat = 30, syscall_shmctl = 31, syscall_dup = 32, syscall_dup2 = 33, syscall_pause = 34, syscall_nanosleep = 35, syscall_getitimer = 36, syscall_alarm = 37, syscall_setitimer = 38, syscall_getpid = 39, syscall_sendfile = 40, syscall_socket = 41, syscall_connect = 42, syscall_accept = 43, syscall_sendto = 44, syscall_recvfrom = 45, syscall_sendmsg = 46, syscall_recvmsg = 47, syscall_shutdown = 48, syscall_bind = 49, syscall_listen = 50, syscall_getsockname = 51, syscall_getpeername = 52, syscall_socketpair = 53, syscall_setsockopt = 54, syscall_getsockopt = 55, syscall_clone = 56, syscall_fork = 57, syscall_vfork = 58, syscall_execve = 59, syscall_exit = 60, syscall_wait4 = 61, syscall_kill = 62, syscall_uname = 63, syscall_semget = 64, syscall_semop = 65, syscall_semctl = 66, syscall_shmdt = 67, syscall_msgget = 68, syscall_msgsnd = 69, syscall_msgrcv = 70, syscall_msgctl = 71, syscall_fcntl = 72, syscall_flock = 73, syscall_fsync = 74, syscall_fdatasync = 75, syscall_truncate = 76, syscall_ftruncate = 77, syscall_getdents = 78, syscall_getcwd = 79, syscall_chdir = 80, syscall_fchdir = 81, syscall_rename = 82, syscall_mkdir = 83, syscall_rmdir = 84, syscall_creat = 85, syscall_link = 86, syscall_unlink = 87, syscall_symlink = 88, syscall_readlink = 89, syscall_chmod = 90, syscall_fchmod = 91, syscall_chown = 92, syscall_fchown = 93, syscall_lchown = 94, syscall_umask = 95, syscall_gettimeofday = 96, syscall_getrlimit = 97, syscall_getrusage = 98, syscall_sysinfo = 99, syscall_times = 100, syscall_ptrace = 101, syscall_getuid = 102, syscall_syslog = 103, syscall_getgid = 104, syscall_setuid = 105, syscall_setgid = 106, syscall_geteuid = 107, syscall_getegid = 108, syscall_setpgid = 109, syscall_getppid = 110, syscall_getpgrp = 111, syscall_setsid = 112, syscall_setreuid = 113, syscall_setregid = 114, syscall_getgroups = 115, syscall_setgroups = 116, syscall_setresuid = 117, syscall_getresuid = 118, syscall_setresgid = 119, syscall_getresgid = 120, syscall_getpgid = 121, syscall_setfsuid = 122, syscall_setfsgid = 123, syscall_getsid = 124, syscall_capget = 125, syscall_capset = 126, syscall_rt_sigpending = 127, syscall_rt_sigtimedwait = 128, syscall_rt_sigqueueinfo = 129, syscall_rt_sigsuspend = 130, syscall_sigaltstack = 131, syscall_utime = 132, syscall_mknod = 133, syscall_uselib = 134, syscall_personality = 135, syscall_ustat = 136, syscall_statfs = 137, syscall_fstatfs = 138, syscall_sysfs = 139, syscall_getpriority = 140, syscall_setpriority = 141, syscall_sched_setparam = 142, syscall_sched_getparam = 143, syscall_sched_setscheduler = 144, syscall_sched_getscheduler = 145, syscall_sched_get_priority_max = 146, syscall_sched_get_priority_min = 147, syscall_sched_rr_get_interval = 148, syscall_mlock = 149, syscall_munlock = 150, syscall_mlockall = 151, syscall_munlockall = 152, syscall_vhangup = 153, syscall_modify_ldt = 154, syscall_pivot_root = 155, syscall__sysctl = 156, syscall_prctl = 157, syscall_arch_prctl = 158, syscall_adjtimex = 159, syscall_setrlimit = 160, syscall_chroot = 161, syscall_sync = 162, syscall_acct = 163, syscall_settimeofday = 164, syscall_mount = 165, syscall_umount2 = 166, syscall_swapon = 167, syscall_swapoff = 168, syscall_reboot = 169, syscall_sethostname = 170, syscall_setdomainname = 171, syscall_iopl = 172, syscall_ioperm = 173, syscall_create_module = 174, syscall_init_module = 175, syscall_delete_module = 176, syscall_get_kernel_syms = 177, syscall_query_module = 178, syscall_quotactl = 179, syscall_nfsservctl = 180, syscall_getpmsg = 181, syscall_putpmsg = 182, syscall_afs_syscall = 183, syscall_tuxcall = 184, syscall_security = 185, syscall_gettid = 186, syscall_readahead = 187, syscall_setxattr = 188, syscall_lsetxattr = 189, syscall_fsetxattr = 190, syscall_getxattr = 191, syscall_lgetxattr = 192, syscall_fgetxattr = 193, syscall_listxattr = 194, syscall_llistxattr = 195, syscall_flistxattr = 196, syscall_removexattr = 197, syscall_lremovexattr = 198, syscall_fremovexattr = 199, syscall_tkill = 200, syscall_time = 201, syscall_futex = 202, syscall_sched_setaffinity = 203, syscall_sched_getaffinity = 204, syscall_set_thread_area = 205, syscall_io_setup = 206, syscall_io_destroy = 207, syscall_io_getevents = 208, syscall_io_submit = 209, syscall_io_cancel = 210, syscall_get_thread_area = 211, syscall_lookup_dcookie = 212, syscall_epoll_create = 213, syscall_epoll_ctl_old = 214, syscall_epoll_wait_old = 215, syscall_remap_file_pages = 216, syscall_getdents64 = 217, syscall_set_tid_address = 218, syscall_restart_syscall = 219, syscall_semtimedop = 220, syscall_fadvise64 = 221, syscall_timer_create = 222, syscall_timer_settime = 223, syscall_timer_gettime = 224, syscall_timer_getoverrun = 225, syscall_timer_delete = 226, syscall_clock_settime = 227, syscall_clock_gettime = 228, syscall_clock_getres = 229, syscall_clock_nanosleep = 230, syscall_exit_group = 231, syscall_epoll_wait = 232, syscall_epoll_ctl = 233, syscall_tgkill = 234, syscall_utimes = 235, syscall_vserver = 236, syscall_mbind = 237, syscall_set_mempolicy = 238, syscall_get_mempolicy = 239, syscall_mq_open = 240, syscall_mq_unlink = 241, syscall_mq_timedsend = 242, syscall_mq_timedreceive = 243, syscall_mq_notify = 244, syscall_mq_getsetattr = 245, syscall_kexec_load = 246, syscall_waitid = 247, syscall_add_key = 248, syscall_request_key = 249, syscall_keyctl = 250, syscall_ioprio_set = 251, syscall_ioprio_get = 252, syscall_inotify_init = 253, syscall_inotify_add_watch = 254, syscall_inotify_rm_watch = 255, syscall_migrate_pages = 256, syscall_openat = 257, syscall_mkdirat = 258, syscall_mknodat = 259, syscall_fchownat = 260, syscall_futimesat = 261, syscall_newfstatat = 262, syscall_unlinkat = 263, syscall_renameat = 264, syscall_linkat = 265, syscall_symlinkat = 266, syscall_readlinkat = 267, syscall_fchmodat = 268, syscall_faccessat = 269, syscall_pselect6 = 270, syscall_ppoll = 271, syscall_unshare = 272, syscall_set_robust_list = 273, syscall_get_robust_list = 274, syscall_splice = 275, syscall_tee = 276, syscall_sync_file_range = 277, syscall_vmsplice = 278, syscall_move_pages = 279, syscall_utimensat = 280, syscall_epoll_pwait = 281, syscall_signalfd = 282, syscall_timerfd_create = 283, syscall_eventfd = 284, syscall_fallocate = 285, syscall_timerfd_settime = 286, syscall_timerfd_gettime = 287, syscall_accept4 = 288, syscall_signalfd4 = 289, syscall_eventfd2 = 290, syscall_epoll_create1 = 291, syscall_dup3 = 292, syscall_pipe2 = 293, syscall_inotify_init1 = 294, syscall_preadv = 295, syscall_pwritev = 296, syscall_rt_tgsigqueueinfo = 297, syscall_perf_event_open = 298, syscall_recvmmsg = 299, syscall_fanotify_init = 300, syscall_fanotify_mark = 301, syscall_prlimit64 = 302, syscall_name_to_handle_at = 303, syscall_open_by_handle_at = 304, syscall_clock_adjtime = 305, syscall_syncfs = 306, syscall_sendmmsg = 307, syscall_setns = 308, syscall_getcpu = 309, syscall_process_vm_readv = 310, syscall_process_vm_writev = 311, syscall_kcmp = 312, syscall_finit_module = 313, syscall_sched_setattr = 314, syscall_sched_getattr = 315, syscall_renameat2 = 316, syscall_seccomp = 317, syscall_getrandom = 318, syscall_memfd_create = 319, syscall_kexec_file_load = 320, syscall_bpf = 321, syscall_execveat = 322, syscall_userfaultfd = 323, syscall_membarrier = 324, syscall_mlock2 = 325, syscall_copy_file_range = 326, syscall_preadv2 = 327, syscall_pwritev2 = 328, syscall_pkey_mprotect = 329, syscall_pkey_alloc = 330, syscall_pkey_free = 331, syscall_statx = 332, syscall_io_pgetevents = 333, syscall_rseq = 334, syscall_pidfd_send_signal = 424, syscall_io_uring_setup = 425, syscall_io_uring_enter = 426, syscall_io_uring_register = 427, syscall_open_tree = 428, syscall_move_mount = 429, syscall_fsopen = 430, syscall_fsconfig = 431, syscall_fsmount = 432, syscall_fspick = 433, syscall_pidfd_open = 434, syscall_clone3 = 435};

#elif defined(__i386__)
    #error i386 build
#elif defined(__arm__)
    #error ARM build currently unsupported
#elif defined(__aarch64__)
    #error ARM64 build currently unsupported
#elif defined(__alpha__)
    #error Alpha build currently unsupported
#elif defined(__hppa__)
    #error HP/PA RISC build currently unsupported
#elif defined(__ia64__)
    #error Itanium build currently unsupported
#elif defined(__m68k__)
    #error Motoral 68k build currently unsupported
#elif defined(__mips__)
    #error MIPS build currently unsupported
#elif defined(__powerpc__)
    #error PPC build currently unsupported
#elif defined(__sparc__)
    #error SPARC build currently unsupported
#else
    #error Unknown and unsupported architecture.
#endif

static inline int64_t read(int32_t fd, void* buf, uint64_t count) { return (int64_t)syscall3(syscall_read, (uint64_t)fd, (uint64_t)buf, (uint64_t)count); } 
static inline int64_t write(int32_t fd, const void* buf, uint64_t count) { return (int64_t)syscall3(syscall_write, (uint64_t)fd, (uint64_t)buf, (uint64_t)count); } 
static inline int32_t open(const int8_t* pathname, int32_t flags) { return (int32_t)syscall2(syscall_open, (uint64_t)pathname, (uint64_t)flags); } 
static inline int32_t close(int32_t fd) { return (int32_t)syscall1(syscall_close, (uint64_t)fd); } 
static inline int32_t stat(const int8_t* pathname, void** statbuf) { return (int32_t)syscall2(syscall_stat, (uint64_t)pathname, (uint64_t)statbuf); } 
static inline int32_t fstat(int32_t fd, void** statbuf) { return (int32_t)syscall2(syscall_fstat, (uint64_t)fd, (uint64_t)statbuf); } 
static inline int32_t lstat(const int8_t* pathname, void** statbuf) { return (int32_t)syscall2(syscall_lstat, (uint64_t)pathname, (uint64_t)statbuf); } 
static inline int32_t poll(void** fds, uint64_t nfds, int32_t timeout) { return (int32_t)syscall3(syscall_poll, (uint64_t)fds, (uint64_t)nfds, (uint64_t)timeout); } 
static inline int64_t lseek(int32_t fd, int64_t offset, int32_t whence) { return (int64_t)syscall3(syscall_lseek, (uint64_t)fd, (uint64_t)offset, (uint64_t)whence); } 
static inline void* mmap(void* addr, uint64_t length, int32_t prot, int32_t flags, int32_t fd, int64_t offset) { return (void*)syscall6(syscall_mmap, (uint64_t)addr, (uint64_t)length, (uint64_t)prot, (uint64_t)flags, (uint64_t)fd, (uint64_t)offset); } 
static inline int32_t mprotect(void* addr, uint64_t len, int32_t prot) { return (int32_t)syscall3(syscall_mprotect, (uint64_t)addr, (uint64_t)len, (uint64_t)prot); } 
static inline int32_t munmap(void* addr, uint64_t length) { return (int32_t)syscall2(syscall_munmap, (uint64_t)addr, (uint64_t)length); } 
static inline int32_t brk(void* addr) { return (int32_t)syscall1(syscall_brk, (uint64_t)addr); } 
/* rt_sigaction parse error, omitted */
static inline int32_t rt_sigprocmask(int32_t how, const void** set, void** oldset, uint64_t sigsetsize) { return (int32_t)syscall4(syscall_rt_sigprocmask, (uint64_t)how, (uint64_t)set, (uint64_t)oldset, (uint64_t)sigsetsize); } 
/* rt_sigreturn parse error, omitted */
/* ioctl parse error, omitted */
static inline int64_t pread64(int32_t fd, void* buf, uint64_t count, int64_t offset) { return (int64_t)syscall4(syscall_pread64, (uint64_t)fd, (uint64_t)buf, (uint64_t)count, (uint64_t)offset); } 
static inline int64_t pwrite64(int32_t fd, const void* buf, uint64_t count, int64_t offset) { return (int64_t)syscall4(syscall_pwrite64, (uint64_t)fd, (uint64_t)buf, (uint64_t)count, (uint64_t)offset); } 
static inline int64_t readv(int32_t fd, const void** iov, int32_t iovcnt) { return (int64_t)syscall3(syscall_readv, (uint64_t)fd, (uint64_t)iov, (uint64_t)iovcnt); } 
static inline int64_t writev(int32_t fd, const void** iov, int32_t iovcnt) { return (int64_t)syscall3(syscall_writev, (uint64_t)fd, (uint64_t)iov, (uint64_t)iovcnt); } 
static inline int32_t access(const int8_t* pathname, int32_t mode) { return (int32_t)syscall2(syscall_access, (uint64_t)pathname, (uint64_t)mode); } 
static inline void* pipe() { return (void*)syscall0(syscall_pipe); } 
static inline int32_t select(int32_t nfds, void** readfds, void** writefds, void** exceptfds, void** timeout) { return (int32_t)syscall5(syscall_select, (uint64_t)nfds, (uint64_t)readfds, (uint64_t)writefds, (uint64_t)exceptfds, (uint64_t)timeout); } 
static inline int32_t sched_yield() { return (int32_t)syscall0(syscall_sched_yield); } 
/* mremap parse error, omitted */
static inline int32_t msync(void* addr, uint64_t length, int32_t flags) { return (int32_t)syscall3(syscall_msync, (uint64_t)addr, (uint64_t)length, (uint64_t)flags); } 
static inline int32_t mincore(void* addr, uint64_t length, uint8_t* vec) { return (int32_t)syscall3(syscall_mincore, (uint64_t)addr, (uint64_t)length, (uint64_t)vec); } 
static inline int32_t madvise(void* addr, uint64_t length, int32_t advice) { return (int32_t)syscall3(syscall_madvise, (uint64_t)addr, (uint64_t)length, (uint64_t)advice); } 
static inline int32_t shmget(int32_t key, uint64_t size, int32_t shmflg) { return (int32_t)syscall3(syscall_shmget, (uint64_t)key, (uint64_t)size, (uint64_t)shmflg); } 
static inline void* shmat(int32_t shmid, const void* shmaddr, int32_t shmflg) { return (void*)syscall3(syscall_shmat, (uint64_t)shmid, (uint64_t)shmaddr, (uint64_t)shmflg); } 
static inline int32_t shmctl(int32_t shmid, int32_t cmd, void** buf) { return (int32_t)syscall3(syscall_shmctl, (uint64_t)shmid, (uint64_t)cmd, (uint64_t)buf); } 
static inline int32_t dup(int32_t oldfd) { return (int32_t)syscall1(syscall_dup, (uint64_t)oldfd); } 
static inline int32_t dup2(int32_t oldfd, int32_t newfd) { return (int32_t)syscall2(syscall_dup2, (uint64_t)oldfd, (uint64_t)newfd); } 
static inline int32_t pause() { return (int32_t)syscall0(syscall_pause); } 
static inline int32_t nanosleep(const void** req, void** rem) { return (int32_t)syscall2(syscall_nanosleep, (uint64_t)req, (uint64_t)rem); } 
static inline int32_t getitimer(int32_t which, void** curr_value) { return (int32_t)syscall2(syscall_getitimer, (uint64_t)which, (uint64_t)curr_value); } 
static inline int32_t alarm(uint32_t seconds) { return (int32_t)syscall1(syscall_alarm, (uint64_t)seconds); } 
static inline int32_t setitimer(int32_t which, const void** new_value, void** old_value) { return (int32_t)syscall3(syscall_setitimer, (uint64_t)which, (uint64_t)new_value, (uint64_t)old_value); } 
static inline int32_t getpid() { return (int32_t)syscall0(syscall_getpid); } 
static inline int64_t sendfile(int32_t out_fd, int32_t in_fd, int64_t* offset, uint64_t count) { return (int64_t)syscall4(syscall_sendfile, (uint64_t)out_fd, (uint64_t)in_fd, (uint64_t)offset, (uint64_t)count); } 
static inline int32_t socket(int32_t domain, int32_t type, int32_t protocol) { return (int32_t)syscall3(syscall_socket, (uint64_t)domain, (uint64_t)type, (uint64_t)protocol); } 
static inline int32_t connect(int32_t sockfd, const void** addr, uint32_t addrlen) { return (int32_t)syscall3(syscall_connect, (uint64_t)sockfd, (uint64_t)addr, (uint64_t)addrlen); } 
static inline int32_t accept(int32_t sockfd, void** addr, uint32_t* addrlen) { return (int32_t)syscall3(syscall_accept, (uint64_t)sockfd, (uint64_t)addr, (uint64_t)addrlen); } 
static inline int64_t sendto(int32_t sockfd, const void* buf, uint64_t len, int32_t flags, const void** dest_addr, uint32_t addrlen) { return (int64_t)syscall6(syscall_sendto, (uint64_t)sockfd, (uint64_t)buf, (uint64_t)len, (uint64_t)flags, (uint64_t)dest_addr, (uint64_t)addrlen); } 
static inline int64_t recvfrom(int32_t sockfd, void* buf, uint64_t len, int32_t flags, void** src_addr, uint32_t* addrlen) { return (int64_t)syscall6(syscall_recvfrom, (uint64_t)sockfd, (uint64_t)buf, (uint64_t)len, (uint64_t)flags, (uint64_t)src_addr, (uint64_t)addrlen); } 
static inline int64_t sendmsg(int32_t sockfd, const void** msg, int32_t flags) { return (int64_t)syscall3(syscall_sendmsg, (uint64_t)sockfd, (uint64_t)msg, (uint64_t)flags); } 
static inline int64_t recvmsg(int32_t sockfd, void** msg, int32_t flags) { return (int64_t)syscall3(syscall_recvmsg, (uint64_t)sockfd, (uint64_t)msg, (uint64_t)flags); } 
static inline int32_t shutdown(int32_t sockfd, int32_t how) { return (int32_t)syscall2(syscall_shutdown, (uint64_t)sockfd, (uint64_t)how); } 
static inline int32_t bind(int32_t sockfd, const void** addr, uint32_t addrlen) { return (int32_t)syscall3(syscall_bind, (uint64_t)sockfd, (uint64_t)addr, (uint64_t)addrlen); } 
static inline int32_t listen(int32_t sockfd, int32_t backlog) { return (int32_t)syscall2(syscall_listen, (uint64_t)sockfd, (uint64_t)backlog); } 
static inline int32_t getsockname(int32_t sockfd, void** addr, uint32_t* addrlen) { return (int32_t)syscall3(syscall_getsockname, (uint64_t)sockfd, (uint64_t)addr, (uint64_t)addrlen); } 
static inline int32_t getpeername(int32_t sockfd, void** addr, uint32_t* addrlen) { return (int32_t)syscall3(syscall_getpeername, (uint64_t)sockfd, (uint64_t)addr, (uint64_t)addrlen); } 
static inline int32_t socketpair(int32_t domain, int32_t type, int32_t protocol, int32_t sv) { return (int32_t)syscall4(syscall_socketpair, (uint64_t)domain, (uint64_t)type, (uint64_t)protocol, (uint64_t)sv); } 
static inline int32_t setsockopt(int32_t sockfd, int32_t level, int32_t optname, const void* optval, uint32_t optlen) { return (int32_t)syscall5(syscall_setsockopt, (uint64_t)sockfd, (uint64_t)level, (uint64_t)optname, (uint64_t)optval, (uint64_t)optlen); } 
static inline int32_t getsockopt(int32_t sockfd, int32_t level, int32_t optname, void* optval, uint32_t* optlen) { return (int32_t)syscall5(syscall_getsockopt, (uint64_t)sockfd, (uint64_t)level, (uint64_t)optname, (uint64_t)optval, (uint64_t)optlen); } 
/* clone parse error, omitted */
static inline int32_t fork() { return (int32_t)syscall0(syscall_fork); } 
static inline int32_t vfork() { return (int32_t)syscall0(syscall_vfork); } 
static inline int32_t execve(const int8_t* pathname, const int8_t* argv, const int8_t* envp) { return (int32_t)syscall3(syscall_execve, (uint64_t)pathname, (uint64_t)argv, (uint64_t)envp); } 
static inline void exit(int32_t status) { syscall1(syscall_exit, (uint64_t)status); } 
static inline int32_t wait4(int32_t pid, int32_t* wstatus, int32_t options, void** rusage) { return (int32_t)syscall4(syscall_wait4, (uint64_t)pid, (uint64_t)wstatus, (uint64_t)options, (uint64_t)rusage); } 
static inline int32_t kill(int32_t pid, int32_t sig) { return (int32_t)syscall2(syscall_kill, (uint64_t)pid, (uint64_t)sig); } 
static inline int32_t uname(void** buf) { return (int32_t)syscall1(syscall_uname, (uint64_t)buf); } 
static inline int32_t semget(int32_t key, int32_t nsems, int32_t semflg) { return (int32_t)syscall3(syscall_semget, (uint64_t)key, (uint64_t)nsems, (uint64_t)semflg); } 
static inline int32_t semop(int32_t semid, void** sops, uint64_t nsops) { return (int32_t)syscall3(syscall_semop, (uint64_t)semid, (uint64_t)sops, (uint64_t)nsops); } 
/* semctl parse error, omitted */
static inline int32_t shmdt(const void* shmaddr) { return (int32_t)syscall1(syscall_shmdt, (uint64_t)shmaddr); } 
static inline int32_t msgget(int32_t key, int32_t msgflg) { return (int32_t)syscall2(syscall_msgget, (uint64_t)key, (uint64_t)msgflg); } 
static inline int32_t msgsnd(int32_t msqid, const void* msgp, uint64_t msgsz, int32_t msgflg) { return (int32_t)syscall4(syscall_msgsnd, (uint64_t)msqid, (uint64_t)msgp, (uint64_t)msgsz, (uint64_t)msgflg); } 
static inline int64_t msgrcv(int32_t msqid, void* msgp, uint64_t msgsz, int64_t msgtyp, int32_t msgflg) { return (int64_t)syscall5(syscall_msgrcv, (uint64_t)msqid, (uint64_t)msgp, (uint64_t)msgsz, (uint64_t)msgtyp, (uint64_t)msgflg); } 
static inline int32_t msgctl(int32_t msqid, int32_t cmd, void** buf) { return (int32_t)syscall3(syscall_msgctl, (uint64_t)msqid, (uint64_t)cmd, (uint64_t)buf); } 
/* fcntl parse error, omitted */
static inline int32_t flock(int32_t fd, int32_t operation) { return (int32_t)syscall2(syscall_flock, (uint64_t)fd, (uint64_t)operation); } 
static inline int32_t fsync(int32_t fd) { return (int32_t)syscall1(syscall_fsync, (uint64_t)fd); } 
static inline int32_t fdatasync(int32_t fd) { return (int32_t)syscall1(syscall_fdatasync, (uint64_t)fd); } 
static inline int32_t truncate(const int8_t* path, int64_t length) { return (int32_t)syscall2(syscall_truncate, (uint64_t)path, (uint64_t)length); } 
static inline int32_t ftruncate(int32_t fd, int64_t length) { return (int32_t)syscall2(syscall_ftruncate, (uint64_t)fd, (uint64_t)length); } 
static inline int32_t getdents(uint32_t fd, void** dirp, uint32_t count) { return (int32_t)syscall3(syscall_getdents, (uint64_t)fd, (uint64_t)dirp, (uint64_t)count); } 
static inline int8_t* getcwd(int8_t* buf, uint64_t size) { return (int8_t*)syscall2(syscall_getcwd, (uint64_t)buf, (uint64_t)size); } 
static inline int32_t chdir(const int8_t* path) { return (int32_t)syscall1(syscall_chdir, (uint64_t)path); } 
static inline int32_t fchdir(int32_t fd) { return (int32_t)syscall1(syscall_fchdir, (uint64_t)fd); } 
static inline int32_t rename(const int8_t* oldpath, const int8_t* newpath) { return (int32_t)syscall2(syscall_rename, (uint64_t)oldpath, (uint64_t)newpath); } 
static inline int32_t mkdir(const int8_t* pathname, uint32_t mode) { return (int32_t)syscall2(syscall_mkdir, (uint64_t)pathname, (uint64_t)mode); } 
static inline int32_t rmdir(const int8_t* pathname) { return (int32_t)syscall1(syscall_rmdir, (uint64_t)pathname); } 
static inline int32_t creat(const int8_t* pathname, uint32_t mode) { return (int32_t)syscall2(syscall_creat, (uint64_t)pathname, (uint64_t)mode); } 
static inline int32_t link(const int8_t* oldpath, const int8_t* newpath) { return (int32_t)syscall2(syscall_link, (uint64_t)oldpath, (uint64_t)newpath); } 
static inline int32_t unlink(const int8_t* pathname) { return (int32_t)syscall1(syscall_unlink, (uint64_t)pathname); } 
static inline int32_t symlink(const int8_t* target, const int8_t* linkpath) { return (int32_t)syscall2(syscall_symlink, (uint64_t)target, (uint64_t)linkpath); } 
static inline int64_t readlink(const int8_t* pathname, int8_t* buf, uint64_t bufsiz) { return (int64_t)syscall3(syscall_readlink, (uint64_t)pathname, (uint64_t)buf, (uint64_t)bufsiz); } 
static inline int32_t chmod(const int8_t* pathname, uint32_t mode) { return (int32_t)syscall2(syscall_chmod, (uint64_t)pathname, (uint64_t)mode); } 
static inline int32_t fchmod(int32_t fd, uint32_t mode) { return (int32_t)syscall2(syscall_fchmod, (uint64_t)fd, (uint64_t)mode); } 
static inline int32_t chown(const int8_t* pathname, uint32_t owner, uint32_t group) { return (int32_t)syscall3(syscall_chown, (uint64_t)pathname, (uint64_t)owner, (uint64_t)group); } 
static inline int32_t fchown(int32_t fd, uint32_t owner, uint32_t group) { return (int32_t)syscall3(syscall_fchown, (uint64_t)fd, (uint64_t)owner, (uint64_t)group); } 
static inline int32_t lchown(const int8_t* pathname, uint32_t owner, uint32_t group) { return (int32_t)syscall3(syscall_lchown, (uint64_t)pathname, (uint64_t)owner, (uint64_t)group); } 
static inline uint32_t umask(uint32_t mask) { return (uint32_t)syscall1(syscall_umask, (uint64_t)mask); } 
static inline int32_t gettimeofday(void** tv, void** tz) { return (int32_t)syscall2(syscall_gettimeofday, (uint64_t)tv, (uint64_t)tz); } 
static inline int32_t getrlimit(int32_t resource, void** rlim) { return (int32_t)syscall2(syscall_getrlimit, (uint64_t)resource, (uint64_t)rlim); } 
static inline int32_t getrusage(int32_t who, void** usage) { return (int32_t)syscall2(syscall_getrusage, (uint64_t)who, (uint64_t)usage); } 
static inline int32_t sysinfo(void** info) { return (int32_t)syscall1(syscall_sysinfo, (uint64_t)info); } 
static inline int64_t times(void** buf) { return (int64_t)syscall1(syscall_times, (uint64_t)buf); } 
static inline int64_t ptrace(uint32_t request, int32_t pid, void* addr, void* data) { return (int64_t)syscall4(syscall_ptrace, (uint64_t)request, (uint64_t)pid, (uint64_t)addr, (uint64_t)data); } 
static inline uint32_t getuid() { return (uint32_t)syscall0(syscall_getuid); } 
static inline int32_t syslog(int32_t type, int8_t* bufp, int32_t len) { return (int32_t)syscall3(syscall_syslog, (uint64_t)type, (uint64_t)bufp, (uint64_t)len); } 
static inline uint32_t getgid() { return (uint32_t)syscall0(syscall_getgid); } 
static inline int32_t setuid(uint32_t uid) { return (int32_t)syscall1(syscall_setuid, (uint64_t)uid); } 
static inline int32_t setgid(uint32_t gid) { return (int32_t)syscall1(syscall_setgid, (uint64_t)gid); } 
static inline uint32_t geteuid() { return (uint32_t)syscall0(syscall_geteuid); } 
static inline uint32_t getegid() { return (uint32_t)syscall0(syscall_getegid); } 
static inline int32_t setpgid(int32_t pid, int32_t pgid) { return (int32_t)syscall2(syscall_setpgid, (uint64_t)pid, (uint64_t)pgid); } 
static inline int32_t getppid() { return (int32_t)syscall0(syscall_getppid); } 
static inline int32_t getpgrp() { return (int32_t)syscall0(syscall_getpgrp); } 
static inline int32_t setsid() { return (int32_t)syscall0(syscall_setsid); } 
static inline int32_t setreuid(uint32_t ruid, uint32_t euid) { return (int32_t)syscall2(syscall_setreuid, (uint64_t)ruid, (uint64_t)euid); } 
static inline int32_t setregid(uint32_t rgid, uint32_t egid) { return (int32_t)syscall2(syscall_setregid, (uint64_t)rgid, (uint64_t)egid); } 
static inline int32_t getgroups(int32_t size, uint32_t list) { return (int32_t)syscall2(syscall_getgroups, (uint64_t)size, (uint64_t)list); } 
static inline int32_t setgroups(uint64_t size, const uint32_t* list) { return (int32_t)syscall2(syscall_setgroups, (uint64_t)size, (uint64_t)list); } 
static inline int32_t setresuid(uint32_t ruid, uint32_t euid, uint32_t suid) { return (int32_t)syscall3(syscall_setresuid, (uint64_t)ruid, (uint64_t)euid, (uint64_t)suid); } 
static inline int32_t getresuid(uint32_t* ruid, uint32_t* euid, uint32_t* suid) { return (int32_t)syscall3(syscall_getresuid, (uint64_t)ruid, (uint64_t)euid, (uint64_t)suid); } 
static inline int32_t setresgid(uint32_t rgid, uint32_t egid, uint32_t sgid) { return (int32_t)syscall3(syscall_setresgid, (uint64_t)rgid, (uint64_t)egid, (uint64_t)sgid); } 
static inline int32_t getresgid(uint32_t* rgid, uint32_t* egid, uint32_t* sgid) { return (int32_t)syscall3(syscall_getresgid, (uint64_t)rgid, (uint64_t)egid, (uint64_t)sgid); } 
static inline int32_t getpgid(int32_t pid) { return (int32_t)syscall1(syscall_getpgid, (uint64_t)pid); } 
static inline int32_t setfsuid(uint32_t fsuid) { return (int32_t)syscall1(syscall_setfsuid, (uint64_t)fsuid); } 
static inline int32_t setfsgid(uint32_t fsgid) { return (int32_t)syscall1(syscall_setfsgid, (uint64_t)fsgid); } 
static inline int32_t getsid(int32_t pid) { return (int32_t)syscall1(syscall_getsid, (uint64_t)pid); } 
static inline int32_t capget(void* hdrp, void* datap) { return (int32_t)syscall2(syscall_capget, (uint64_t)hdrp, (uint64_t)datap); } 
static inline int32_t capset(void* hdrp, const void* datap) { return (int32_t)syscall2(syscall_capset, (uint64_t)hdrp, (uint64_t)datap); } 
/* rt_sigpending parse error, omitted */
/* rt_sigtimedwait parse error, omitted */
static inline int32_t rt_sigqueueinfo(int32_t tgid, int32_t sig, void** info) { return (int32_t)syscall3(syscall_rt_sigqueueinfo, (uint64_t)tgid, (uint64_t)sig, (uint64_t)info); } 
/* rt_sigsuspend parse error, omitted */
static inline int32_t sigaltstack(const void** ss, void** old_ss) { return (int32_t)syscall2(syscall_sigaltstack, (uint64_t)ss, (uint64_t)old_ss); } 
static inline int32_t utime(const int8_t* filename, const void** times) { return (int32_t)syscall2(syscall_utime, (uint64_t)filename, (uint64_t)times); } 
static inline int32_t mknod(const int8_t* pathname, uint32_t mode, uint32_t dev) { return (int32_t)syscall3(syscall_mknod, (uint64_t)pathname, (uint64_t)mode, (uint64_t)dev); } 
static inline int32_t uselib(const int8_t* library) { return (int32_t)syscall1(syscall_uselib, (uint64_t)library); } 
static inline int32_t personality(uint64_t persona) { return (int32_t)syscall1(syscall_personality, (uint64_t)persona); } 
static inline int32_t ustat(uint32_t dev, void** ubuf) { return (int32_t)syscall2(syscall_ustat, (uint64_t)dev, (uint64_t)ubuf); } 
static inline int32_t statfs(const int8_t* path, void** buf) { return (int32_t)syscall2(syscall_statfs, (uint64_t)path, (uint64_t)buf); } 
static inline int32_t fstatfs(int32_t fd, void** buf) { return (int32_t)syscall2(syscall_fstatfs, (uint64_t)fd, (uint64_t)buf); } 
static inline int32_t sysfs(int32_t option, const int8_t* fsname) { return (int32_t)syscall2(syscall_sysfs, (uint64_t)option, (uint64_t)fsname); } 
static inline int32_t getpriority(int32_t which, uint32_t who) { return (int32_t)syscall2(syscall_getpriority, (uint64_t)which, (uint64_t)who); } 
static inline int32_t setpriority(int32_t which, uint32_t who, int32_t prio) { return (int32_t)syscall3(syscall_setpriority, (uint64_t)which, (uint64_t)who, (uint64_t)prio); } 
static inline int32_t sched_setparam(int32_t pid, const void** param) { return (int32_t)syscall2(syscall_sched_setparam, (uint64_t)pid, (uint64_t)param); } 
static inline int32_t sched_getparam(int32_t pid, void** param) { return (int32_t)syscall2(syscall_sched_getparam, (uint64_t)pid, (uint64_t)param); } 
static inline int32_t sched_setscheduler(int32_t pid, int32_t policy, const void** param) { return (int32_t)syscall3(syscall_sched_setscheduler, (uint64_t)pid, (uint64_t)policy, (uint64_t)param); } 
static inline int32_t sched_getscheduler(int32_t pid) { return (int32_t)syscall1(syscall_sched_getscheduler, (uint64_t)pid); } 
static inline int32_t sched_get_priority_max(int32_t policy) { return (int32_t)syscall1(syscall_sched_get_priority_max, (uint64_t)policy); } 
static inline int32_t sched_get_priority_min(int32_t policy) { return (int32_t)syscall1(syscall_sched_get_priority_min, (uint64_t)policy); } 
static inline int32_t sched_rr_get_interval(int32_t pid, void** tp) { return (int32_t)syscall2(syscall_sched_rr_get_interval, (uint64_t)pid, (uint64_t)tp); } 
static inline int32_t mlock(const void* addr, uint64_t len) { return (int32_t)syscall2(syscall_mlock, (uint64_t)addr, (uint64_t)len); } 
static inline int32_t munlock(const void* addr, uint64_t len) { return (int32_t)syscall2(syscall_munlock, (uint64_t)addr, (uint64_t)len); } 
static inline int32_t mlockall(int32_t flags) { return (int32_t)syscall1(syscall_mlockall, (uint64_t)flags); } 
static inline int32_t munlockall() { return (int32_t)syscall0(syscall_munlockall); } 
static inline int32_t vhangup() { return (int32_t)syscall0(syscall_vhangup); } 
static inline int32_t modify_ldt(int32_t func, void* ptr, uint64_t bytecount) { return (int32_t)syscall3(syscall_modify_ldt, (uint64_t)func, (uint64_t)ptr, (uint64_t)bytecount); } 
static inline int32_t pivot_root(const int8_t* new_root, const int8_t* put_old) { return (int32_t)syscall2(syscall_pivot_root, (uint64_t)new_root, (uint64_t)put_old); } 
static inline int32_t _sysctl(void** args) { return (int32_t)syscall1(syscall__sysctl, (uint64_t)args); } 
static inline int32_t prctl(int32_t option, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5) { return (int32_t)syscall5(syscall_prctl, (uint64_t)option, (uint64_t)arg2, (uint64_t)arg3, (uint64_t)arg4, (uint64_t)arg5); } 
static inline int32_t arch_prctl(int32_t code, uint64_t addr) { return (int32_t)syscall2(syscall_arch_prctl, (uint64_t)code, (uint64_t)addr); } 
static inline int32_t adjtimex(void** buf) { return (int32_t)syscall1(syscall_adjtimex, (uint64_t)buf); } 
static inline int32_t setrlimit(int32_t resource, const void** rlim) { return (int32_t)syscall2(syscall_setrlimit, (uint64_t)resource, (uint64_t)rlim); } 
static inline int32_t chroot(const int8_t* path) { return (int32_t)syscall1(syscall_chroot, (uint64_t)path); } 
static inline void sync() { syscall0(syscall_sync); } 
static inline int32_t acct(const int8_t* filename) { return (int32_t)syscall1(syscall_acct, (uint64_t)filename); } 
static inline int32_t settimeofday(const void** tv, const void** tz) { return (int32_t)syscall2(syscall_settimeofday, (uint64_t)tv, (uint64_t)tz); } 
static inline int32_t mount(const int8_t* source, const int8_t* target, const int8_t* filesystemtype, uint64_t mountflags, const void* data) { return (int32_t)syscall5(syscall_mount, (uint64_t)source, (uint64_t)target, (uint64_t)filesystemtype, (uint64_t)mountflags, (uint64_t)data); } 
static inline int32_t umount2(const int8_t* target, int32_t flags) { return (int32_t)syscall2(syscall_umount2, (uint64_t)target, (uint64_t)flags); } 
static inline int32_t swapon(const int8_t* path, int32_t swapflags) { return (int32_t)syscall2(syscall_swapon, (uint64_t)path, (uint64_t)swapflags); } 
static inline int32_t swapoff(const int8_t* path) { return (int32_t)syscall1(syscall_swapoff, (uint64_t)path); } 
static inline int32_t reboot(int32_t magic, int32_t magic2, int32_t cmd, void* arg) { return (int32_t)syscall4(syscall_reboot, (uint64_t)magic, (uint64_t)magic2, (uint64_t)cmd, (uint64_t)arg); } 
static inline int32_t sethostname(const int8_t* name, uint64_t len) { return (int32_t)syscall2(syscall_sethostname, (uint64_t)name, (uint64_t)len); } 
static inline int32_t setdomainname(const int8_t* name, uint64_t len) { return (int32_t)syscall2(syscall_setdomainname, (uint64_t)name, (uint64_t)len); } 
static inline int32_t iopl(int32_t level) { return (int32_t)syscall1(syscall_iopl, (uint64_t)level); } 
static inline int32_t ioperm(uint64_t from, uint64_t num, int32_t turn_on) { return (int32_t)syscall3(syscall_ioperm, (uint64_t)from, (uint64_t)num, (uint64_t)turn_on); } 
static inline void* create_module(const int8_t* name, uint64_t size) { return (void*)syscall2(syscall_create_module, (uint64_t)name, (uint64_t)size); } 
static inline int32_t init_module(void* module_image, uint64_t len, const int8_t* param_values) { return (int32_t)syscall3(syscall_init_module, (uint64_t)module_image, (uint64_t)len, (uint64_t)param_values); } 
static inline int32_t delete_module(const int8_t* name, int32_t flags) { return (int32_t)syscall2(syscall_delete_module, (uint64_t)name, (uint64_t)flags); } 
static inline int32_t get_kernel_syms(void** table) { return (int32_t)syscall1(syscall_get_kernel_syms, (uint64_t)table); } 
static inline int32_t query_module(const int8_t* name, int32_t which, void* buf, uint64_t bufsize, uint64_t* ret) { return (int32_t)syscall5(syscall_query_module, (uint64_t)name, (uint64_t)which, (uint64_t)buf, (uint64_t)bufsize, (uint64_t)ret); } 
static inline int32_t quotactl(int32_t cmd, const int8_t* special, int32_t id, void* addr) { return (int32_t)syscall4(syscall_quotactl, (uint64_t)cmd, (uint64_t)special, (uint64_t)id, (uint64_t)addr); } 
static inline int64_t nfsservctl(int32_t cmd, void** argp, void** resp) { return (int64_t)syscall3(syscall_nfsservctl, (uint64_t)cmd, (uint64_t)argp, (uint64_t)resp); } 
/* getpmsg parse error, omitted */
/* putpmsg parse error, omitted */
/* afs_syscall parse error, omitted */
/* tuxcall parse error, omitted */
/* security parse error, omitted */
static inline int32_t gettid() { return (int32_t)syscall0(syscall_gettid); } 
static inline int64_t readahead(int32_t fd, int64_t offset, uint64_t count) { return (int64_t)syscall3(syscall_readahead, (uint64_t)fd, (uint64_t)offset, (uint64_t)count); } 
static inline int32_t setxattr(const int8_t* path, const int8_t* name, const void* value, uint64_t size, int32_t flags) { return (int32_t)syscall5(syscall_setxattr, (uint64_t)path, (uint64_t)name, (uint64_t)value, (uint64_t)size, (uint64_t)flags); } 
static inline int32_t lsetxattr(const int8_t* path, const int8_t* name, const void* value, uint64_t size, int32_t flags) { return (int32_t)syscall5(syscall_lsetxattr, (uint64_t)path, (uint64_t)name, (uint64_t)value, (uint64_t)size, (uint64_t)flags); } 
static inline int32_t fsetxattr(int32_t fd, const int8_t* name, const void* value, uint64_t size, int32_t flags) { return (int32_t)syscall5(syscall_fsetxattr, (uint64_t)fd, (uint64_t)name, (uint64_t)value, (uint64_t)size, (uint64_t)flags); } 
static inline int64_t getxattr(const int8_t* path, const int8_t* name, void* value, uint64_t size) { return (int64_t)syscall4(syscall_getxattr, (uint64_t)path, (uint64_t)name, (uint64_t)value, (uint64_t)size); } 
static inline int64_t lgetxattr(const int8_t* path, const int8_t* name, void* value, uint64_t size) { return (int64_t)syscall4(syscall_lgetxattr, (uint64_t)path, (uint64_t)name, (uint64_t)value, (uint64_t)size); } 
static inline int64_t fgetxattr(int32_t fd, const int8_t* name, void* value, uint64_t size) { return (int64_t)syscall4(syscall_fgetxattr, (uint64_t)fd, (uint64_t)name, (uint64_t)value, (uint64_t)size); } 
static inline int64_t listxattr(const int8_t* path, int8_t* list, uint64_t size) { return (int64_t)syscall3(syscall_listxattr, (uint64_t)path, (uint64_t)list, (uint64_t)size); } 
static inline int64_t llistxattr(const int8_t* path, int8_t* list, uint64_t size) { return (int64_t)syscall3(syscall_llistxattr, (uint64_t)path, (uint64_t)list, (uint64_t)size); } 
static inline int64_t flistxattr(int32_t fd, int8_t* list, uint64_t size) { return (int64_t)syscall3(syscall_flistxattr, (uint64_t)fd, (uint64_t)list, (uint64_t)size); } 
static inline int32_t removexattr(const int8_t* path, const int8_t* name) { return (int32_t)syscall2(syscall_removexattr, (uint64_t)path, (uint64_t)name); } 
static inline int32_t lremovexattr(const int8_t* path, const int8_t* name) { return (int32_t)syscall2(syscall_lremovexattr, (uint64_t)path, (uint64_t)name); } 
static inline int32_t fremovexattr(int32_t fd, const int8_t* name) { return (int32_t)syscall2(syscall_fremovexattr, (uint64_t)fd, (uint64_t)name); } 
static inline int32_t tkill(int32_t tid, int32_t sig) { return (int32_t)syscall2(syscall_tkill, (uint64_t)tid, (uint64_t)sig); } 
static inline int64_t time(int64_t* tloc) { return (int64_t)syscall1(syscall_time, (uint64_t)tloc); } 
/* futex parse error, omitted */
static inline int32_t sched_setaffinity(int32_t pid, uint64_t cpusetsize, const void** mask) { return (int32_t)syscall3(syscall_sched_setaffinity, (uint64_t)pid, (uint64_t)cpusetsize, (uint64_t)mask); } 
static inline int32_t sched_getaffinity(int32_t pid, uint64_t cpusetsize, void** mask) { return (int32_t)syscall3(syscall_sched_getaffinity, (uint64_t)pid, (uint64_t)cpusetsize, (uint64_t)mask); } 
static inline int32_t set_thread_area(void** u_info) { return (int32_t)syscall1(syscall_set_thread_area, (uint64_t)u_info); } 
static inline int32_t io_setup(uint32_t nr_events, uint64_t* ctx_idp) { return (int32_t)syscall2(syscall_io_setup, (uint64_t)nr_events, (uint64_t)ctx_idp); } 
static inline int32_t io_destroy(uint64_t ctx_id) { return (int32_t)syscall1(syscall_io_destroy, (uint64_t)ctx_id); } 
static inline int32_t io_getevents(uint64_t ctx_id, int64_t min_nr, int64_t nr, void** events, void** timeout) { return (int32_t)syscall5(syscall_io_getevents, (uint64_t)ctx_id, (uint64_t)min_nr, (uint64_t)nr, (uint64_t)events, (uint64_t)timeout); } 
static inline int32_t io_submit(uint64_t ctx_id, int64_t nr, void** iocbpp) { return (int32_t)syscall3(syscall_io_submit, (uint64_t)ctx_id, (uint64_t)nr, (uint64_t)iocbpp); } 
static inline int32_t io_cancel(uint64_t ctx_id, void** iocb, void** result) { return (int32_t)syscall3(syscall_io_cancel, (uint64_t)ctx_id, (uint64_t)iocb, (uint64_t)result); } 
static inline int32_t get_thread_area(void** u_info) { return (int32_t)syscall1(syscall_get_thread_area, (uint64_t)u_info); } 
static inline int32_t lookup_dcookie(uint64_t cookie, int8_t* buffer, uint64_t len) { return (int32_t)syscall3(syscall_lookup_dcookie, (uint64_t)cookie, (uint64_t)buffer, (uint64_t)len); } 
static inline int32_t epoll_create(int32_t size) { return (int32_t)syscall1(syscall_epoll_create, (uint64_t)size); } 
/* epoll_ctl_old parse error, omitted */
/* epoll_wait_old parse error, omitted */
static inline int32_t remap_file_pages(void* addr, uint64_t size, int32_t prot, uint64_t pgoff, int32_t flags) { return (int32_t)syscall5(syscall_remap_file_pages, (uint64_t)addr, (uint64_t)size, (uint64_t)prot, (uint64_t)pgoff, (uint64_t)flags); } 
static inline int32_t getdents64(uint32_t fd, void** dirp, uint32_t count) { return (int32_t)syscall3(syscall_getdents64, (uint64_t)fd, (uint64_t)dirp, (uint64_t)count); } 
static inline int64_t set_tid_address(int32_t* tidptr) { return (int64_t)syscall1(syscall_set_tid_address, (uint64_t)tidptr); } 
static inline int32_t restart_syscall() { return (int32_t)syscall0(syscall_restart_syscall); } 
static inline int32_t semtimedop(int32_t semid, void** sops, uint64_t nsops, const void** timeout) { return (int32_t)syscall4(syscall_semtimedop, (uint64_t)semid, (uint64_t)sops, (uint64_t)nsops, (uint64_t)timeout); } 
/* fadvise64 parse error, omitted */
static inline int32_t timer_create(int32_t clockid, void** sevp, int32_t* timerid) { return (int32_t)syscall3(syscall_timer_create, (uint64_t)clockid, (uint64_t)sevp, (uint64_t)timerid); } 
static inline int32_t timer_settime(int32_t timerid, int32_t flags, const void** new_value, void** old_value) { return (int32_t)syscall4(syscall_timer_settime, (uint64_t)timerid, (uint64_t)flags, (uint64_t)new_value, (uint64_t)old_value); } 
static inline int32_t timer_gettime(int32_t timerid, void** curr_value) { return (int32_t)syscall2(syscall_timer_gettime, (uint64_t)timerid, (uint64_t)curr_value); } 
static inline int32_t timer_getoverrun(int32_t timerid) { return (int32_t)syscall1(syscall_timer_getoverrun, (uint64_t)timerid); } 
static inline int32_t timer_delete(int32_t timerid) { return (int32_t)syscall1(syscall_timer_delete, (uint64_t)timerid); } 
static inline int32_t clock_settime(int32_t clk_id, const void** tp) { return (int32_t)syscall2(syscall_clock_settime, (uint64_t)clk_id, (uint64_t)tp); } 
static inline int32_t clock_gettime(int32_t clk_id, void** tp) { return (int32_t)syscall2(syscall_clock_gettime, (uint64_t)clk_id, (uint64_t)tp); } 
static inline int32_t clock_getres(int32_t clk_id, void** res) { return (int32_t)syscall2(syscall_clock_getres, (uint64_t)clk_id, (uint64_t)res); } 
static inline int32_t clock_nanosleep(int32_t clock_id, int32_t flags, const void** request, void** remain) { return (int32_t)syscall4(syscall_clock_nanosleep, (uint64_t)clock_id, (uint64_t)flags, (uint64_t)request, (uint64_t)remain); } 
static inline void exit_group(int32_t status) { syscall1(syscall_exit_group, (uint64_t)status); } 
static inline int32_t epoll_wait(int32_t epfd, void** events, int32_t maxevents, int32_t timeout) { return (int32_t)syscall4(syscall_epoll_wait, (uint64_t)epfd, (uint64_t)events, (uint64_t)maxevents, (uint64_t)timeout); } 
static inline int32_t epoll_ctl(int32_t epfd, int32_t op, int32_t fd, void** event) { return (int32_t)syscall4(syscall_epoll_ctl, (uint64_t)epfd, (uint64_t)op, (uint64_t)fd, (uint64_t)event); } 
static inline int32_t tgkill(int32_t tgid, int32_t tid, int32_t sig) { return (int32_t)syscall3(syscall_tgkill, (uint64_t)tgid, (uint64_t)tid, (uint64_t)sig); } 
static inline int32_t utimes(const int8_t* filename, const void* times) { return (int32_t)syscall2(syscall_utimes, (uint64_t)filename, (uint64_t)times); } 
/* vserver parse error, omitted */
static inline int64_t mbind(void* addr, uint64_t len, int32_t mode, const uint64_t* nodemask, uint64_t maxnode, uint32_t flags) { return (int64_t)syscall6(syscall_mbind, (uint64_t)addr, (uint64_t)len, (uint64_t)mode, (uint64_t)nodemask, (uint64_t)maxnode, (uint64_t)flags); } 
static inline int64_t set_mempolicy(int32_t mode, const uint64_t* nodemask, uint64_t maxnode) { return (int64_t)syscall3(syscall_set_mempolicy, (uint64_t)mode, (uint64_t)nodemask, (uint64_t)maxnode); } 
static inline int64_t get_mempolicy(int32_t* mode, uint64_t* nodemask, uint64_t maxnode, void* addr, uint64_t flags) { return (int64_t)syscall5(syscall_get_mempolicy, (uint64_t)mode, (uint64_t)nodemask, (uint64_t)maxnode, (uint64_t)addr, (uint64_t)flags); } 
static inline int32_t mq_open(const int8_t* name, int32_t oflag) { return (int32_t)syscall2(syscall_mq_open, (uint64_t)name, (uint64_t)oflag); } 
static inline int32_t mq_unlink(const int8_t* name) { return (int32_t)syscall1(syscall_mq_unlink, (uint64_t)name); } 
static inline int32_t mq_timedsend(int32_t mqdes, const int8_t* msg_ptr, uint64_t msg_len, uint32_t msg_prio, const void** abs_timeout) { return (int32_t)syscall5(syscall_mq_timedsend, (uint64_t)mqdes, (uint64_t)msg_ptr, (uint64_t)msg_len, (uint64_t)msg_prio, (uint64_t)abs_timeout); } 
static inline int64_t mq_timedreceive(int32_t mqdes, int8_t* msg_ptr, uint64_t msg_len, uint32_t* msg_prio, const void** abs_timeout) { return (int64_t)syscall5(syscall_mq_timedreceive, (uint64_t)mqdes, (uint64_t)msg_ptr, (uint64_t)msg_len, (uint64_t)msg_prio, (uint64_t)abs_timeout); } 
static inline int32_t mq_notify(int32_t mqdes, const void** sevp) { return (int32_t)syscall2(syscall_mq_notify, (uint64_t)mqdes, (uint64_t)sevp); } 
static inline int32_t mq_getsetattr(int32_t mqdes, void** newattr, void** oldattr) { return (int32_t)syscall3(syscall_mq_getsetattr, (uint64_t)mqdes, (uint64_t)newattr, (uint64_t)oldattr); } 
static inline int64_t kexec_load(uint64_t entry, uint64_t nr_segments, void** segments, uint64_t flags) { return (int64_t)syscall4(syscall_kexec_load, (uint64_t)entry, (uint64_t)nr_segments, (uint64_t)segments, (uint64_t)flags); } 
static inline int32_t waitid(uint32_t idtype, uint32_t id, void** infop, int32_t options) { return (int32_t)syscall4(syscall_waitid, (uint64_t)idtype, (uint64_t)id, (uint64_t)infop, (uint64_t)options); } 
static inline int32_t add_key(const int8_t* type, const int8_t* description, const void* payload, uint64_t plen, int32_t keyring) { return (int32_t)syscall5(syscall_add_key, (uint64_t)type, (uint64_t)description, (uint64_t)payload, (uint64_t)plen, (uint64_t)keyring); } 
static inline int32_t request_key(const int8_t* type, const int8_t* description, const int8_t* callout_info, int32_t dest_keyring) { return (int32_t)syscall4(syscall_request_key, (uint64_t)type, (uint64_t)description, (uint64_t)callout_info, (uint64_t)dest_keyring); } 
/* keyctl parse error, omitted */
static inline int32_t ioprio_set(int32_t which, int32_t who, int32_t ioprio) { return (int32_t)syscall3(syscall_ioprio_set, (uint64_t)which, (uint64_t)who, (uint64_t)ioprio); } 
static inline int32_t ioprio_get(int32_t which, int32_t who) { return (int32_t)syscall2(syscall_ioprio_get, (uint64_t)which, (uint64_t)who); } 
static inline int32_t inotify_init() { return (int32_t)syscall0(syscall_inotify_init); } 
static inline int32_t inotify_add_watch(int32_t fd, const int8_t* pathname, uint32_t mask) { return (int32_t)syscall3(syscall_inotify_add_watch, (uint64_t)fd, (uint64_t)pathname, (uint64_t)mask); } 
static inline int32_t inotify_rm_watch(int32_t fd, int32_t wd) { return (int32_t)syscall2(syscall_inotify_rm_watch, (uint64_t)fd, (uint64_t)wd); } 
static inline int64_t migrate_pages(int32_t pid, uint64_t maxnode, const uint64_t* old_nodes, const uint64_t* new_nodes) { return (int64_t)syscall4(syscall_migrate_pages, (uint64_t)pid, (uint64_t)maxnode, (uint64_t)old_nodes, (uint64_t)new_nodes); } 
static inline int32_t openat(int32_t dirfd, const int8_t* pathname, int32_t flags) { return (int32_t)syscall3(syscall_openat, (uint64_t)dirfd, (uint64_t)pathname, (uint64_t)flags); } 
static inline int32_t mkdirat(int32_t dirfd, const int8_t* pathname, uint32_t mode) { return (int32_t)syscall3(syscall_mkdirat, (uint64_t)dirfd, (uint64_t)pathname, (uint64_t)mode); } 
static inline int32_t mknodat(int32_t dirfd, const int8_t* pathname, uint32_t mode, uint32_t dev) { return (int32_t)syscall4(syscall_mknodat, (uint64_t)dirfd, (uint64_t)pathname, (uint64_t)mode, (uint64_t)dev); } 
static inline int32_t fchownat(int32_t dirfd, const int8_t* pathname, uint32_t owner, uint32_t group, int32_t flags) { return (int32_t)syscall5(syscall_fchownat, (uint64_t)dirfd, (uint64_t)pathname, (uint64_t)owner, (uint64_t)group, (uint64_t)flags); } 
static inline int32_t futimesat(int32_t dirfd, const int8_t* pathname, const void* times) { return (int32_t)syscall3(syscall_futimesat, (uint64_t)dirfd, (uint64_t)pathname, (uint64_t)times); } 
/* newfstatat parse error, omitted */
static inline int32_t unlinkat(int32_t dirfd, const int8_t* pathname, int32_t flags) { return (int32_t)syscall3(syscall_unlinkat, (uint64_t)dirfd, (uint64_t)pathname, (uint64_t)flags); } 
static inline int32_t renameat(int32_t olddirfd, const int8_t* oldpath, int32_t newdirfd, const int8_t* newpath) { return (int32_t)syscall4(syscall_renameat, (uint64_t)olddirfd, (uint64_t)oldpath, (uint64_t)newdirfd, (uint64_t)newpath); } 
static inline int32_t linkat(int32_t olddirfd, const int8_t* oldpath, int32_t newdirfd, const int8_t* newpath, int32_t flags) { return (int32_t)syscall5(syscall_linkat, (uint64_t)olddirfd, (uint64_t)oldpath, (uint64_t)newdirfd, (uint64_t)newpath, (uint64_t)flags); } 
static inline int32_t symlinkat(const int8_t* target, int32_t newdirfd, const int8_t* linkpath) { return (int32_t)syscall3(syscall_symlinkat, (uint64_t)target, (uint64_t)newdirfd, (uint64_t)linkpath); } 
static inline int64_t readlinkat(int32_t dirfd, const int8_t* pathname, int8_t* buf, uint64_t bufsiz) { return (int64_t)syscall4(syscall_readlinkat, (uint64_t)dirfd, (uint64_t)pathname, (uint64_t)buf, (uint64_t)bufsiz); } 
static inline int32_t fchmodat(int32_t dirfd, const int8_t* pathname, uint32_t mode, int32_t flags) { return (int32_t)syscall4(syscall_fchmodat, (uint64_t)dirfd, (uint64_t)pathname, (uint64_t)mode, (uint64_t)flags); } 
static inline int32_t faccessat(int32_t dirfd, const int8_t* pathname, int32_t mode, int32_t flags) { return (int32_t)syscall4(syscall_faccessat, (uint64_t)dirfd, (uint64_t)pathname, (uint64_t)mode, (uint64_t)flags); } 
/* pselect6 parse error, omitted */
static inline int32_t ppoll(void** fds, uint64_t nfds, const void** tmo_p, const uint64_t* sigmask) { return (int32_t)syscall4(syscall_ppoll, (uint64_t)fds, (uint64_t)nfds, (uint64_t)tmo_p, (uint64_t)sigmask); } 
static inline int32_t unshare(int32_t flags) { return (int32_t)syscall1(syscall_unshare, (uint64_t)flags); } 
static inline int64_t set_robust_list(void** head, uint64_t len) { return (int64_t)syscall2(syscall_set_robust_list, (uint64_t)head, (uint64_t)len); } 
static inline int64_t get_robust_list(int32_t pid, void** head_ptr, uint64_t* len_ptr) { return (int64_t)syscall3(syscall_get_robust_list, (uint64_t)pid, (uint64_t)head_ptr, (uint64_t)len_ptr); } 
static inline int64_t splice(int32_t fd_in, int64_t* off_in, int32_t fd_out, int64_t* off_out, uint64_t len, uint32_t flags) { return (int64_t)syscall6(syscall_splice, (uint64_t)fd_in, (uint64_t)off_in, (uint64_t)fd_out, (uint64_t)off_out, (uint64_t)len, (uint64_t)flags); } 
static inline int64_t tee(int32_t fd_in, int32_t fd_out, uint64_t len, uint32_t flags) { return (int64_t)syscall4(syscall_tee, (uint64_t)fd_in, (uint64_t)fd_out, (uint64_t)len, (uint64_t)flags); } 
static inline int32_t sync_file_range(int32_t fd, int64_t offset, int64_t nbytes, uint32_t flags) { return (int32_t)syscall4(syscall_sync_file_range, (uint64_t)fd, (uint64_t)offset, (uint64_t)nbytes, (uint64_t)flags); } 
static inline int64_t vmsplice(int32_t fd, const void** iov, uint64_t nr_segs, uint32_t flags) { return (int64_t)syscall4(syscall_vmsplice, (uint64_t)fd, (uint64_t)iov, (uint64_t)nr_segs, (uint64_t)flags); } 
static inline int64_t move_pages(int32_t pid, uint64_t count, void* pages, const int32_t* nodes, int32_t* status, int32_t flags) { return (int64_t)syscall6(syscall_move_pages, (uint64_t)pid, (uint64_t)count, (uint64_t)pages, (uint64_t)nodes, (uint64_t)status, (uint64_t)flags); } 
static inline int32_t utimensat(int32_t dirfd, const int8_t* pathname, const void* times, int32_t flags) { return (int32_t)syscall4(syscall_utimensat, (uint64_t)dirfd, (uint64_t)pathname, (uint64_t)times, (uint64_t)flags); } 
static inline int32_t epoll_pwait(int32_t epfd, void** events, int32_t maxevents, int32_t timeout, const uint64_t* sigmask) { return (int32_t)syscall5(syscall_epoll_pwait, (uint64_t)epfd, (uint64_t)events, (uint64_t)maxevents, (uint64_t)timeout, (uint64_t)sigmask); } 
static inline int32_t signalfd(int32_t fd, const uint64_t* mask, int32_t flags) { return (int32_t)syscall3(syscall_signalfd, (uint64_t)fd, (uint64_t)mask, (uint64_t)flags); } 
static inline int32_t timerfd_create(int32_t clockid, int32_t flags) { return (int32_t)syscall2(syscall_timerfd_create, (uint64_t)clockid, (uint64_t)flags); } 
static inline int32_t eventfd(uint32_t initval, int32_t flags) { return (int32_t)syscall2(syscall_eventfd, (uint64_t)initval, (uint64_t)flags); } 
static inline int32_t fallocate(int32_t fd, int32_t mode, int64_t offset, int64_t len) { return (int32_t)syscall4(syscall_fallocate, (uint64_t)fd, (uint64_t)mode, (uint64_t)offset, (uint64_t)len); } 
static inline int32_t timerfd_settime(int32_t fd, int32_t flags, const void** new_value, void** old_value) { return (int32_t)syscall4(syscall_timerfd_settime, (uint64_t)fd, (uint64_t)flags, (uint64_t)new_value, (uint64_t)old_value); } 
static inline int32_t timerfd_gettime(int32_t fd, void** curr_value) { return (int32_t)syscall2(syscall_timerfd_gettime, (uint64_t)fd, (uint64_t)curr_value); } 
static inline int32_t accept4(int32_t sockfd, void** addr, uint32_t* addrlen, int32_t flags) { return (int32_t)syscall4(syscall_accept4, (uint64_t)sockfd, (uint64_t)addr, (uint64_t)addrlen, (uint64_t)flags); } 
/* signalfd4 parse error, omitted */
/* eventfd2 parse error, omitted */
static inline int32_t epoll_create1(int32_t flags) { return (int32_t)syscall1(syscall_epoll_create1, (uint64_t)flags); } 
static inline int32_t dup3(int32_t oldfd, int32_t newfd, int32_t flags) { return (int32_t)syscall3(syscall_dup3, (uint64_t)oldfd, (uint64_t)newfd, (uint64_t)flags); } 
static inline int32_t pipe2(int32_t pipefd, int32_t flags) { return (int32_t)syscall2(syscall_pipe2, (uint64_t)pipefd, (uint64_t)flags); } 
static inline int32_t inotify_init1(int32_t flags) { return (int32_t)syscall1(syscall_inotify_init1, (uint64_t)flags); } 
static inline int64_t preadv(int32_t fd, const void** iov, int32_t iovcnt, int64_t offset) { return (int64_t)syscall4(syscall_preadv, (uint64_t)fd, (uint64_t)iov, (uint64_t)iovcnt, (uint64_t)offset); } 
static inline int64_t pwritev(int32_t fd, const void** iov, int32_t iovcnt, int64_t offset) { return (int64_t)syscall4(syscall_pwritev, (uint64_t)fd, (uint64_t)iov, (uint64_t)iovcnt, (uint64_t)offset); } 
static inline int32_t rt_tgsigqueueinfo(int32_t tgid, int32_t tid, int32_t sig, void** info) { return (int32_t)syscall4(syscall_rt_tgsigqueueinfo, (uint64_t)tgid, (uint64_t)tid, (uint64_t)sig, (uint64_t)info); } 
static inline int32_t perf_event_open(void** attr, int32_t pid, int32_t cpu, int32_t group_fd, uint64_t flags) { return (int32_t)syscall5(syscall_perf_event_open, (uint64_t)attr, (uint64_t)pid, (uint64_t)cpu, (uint64_t)group_fd, (uint64_t)flags); } 
static inline int32_t recvmmsg(int32_t sockfd, void** msgvec, uint32_t vlen, int32_t flags, void** timeout) { return (int32_t)syscall5(syscall_recvmmsg, (uint64_t)sockfd, (uint64_t)msgvec, (uint64_t)vlen, (uint64_t)flags, (uint64_t)timeout); } 
static inline int32_t fanotify_init(uint32_t flags, uint32_t event_f_flags) { return (int32_t)syscall2(syscall_fanotify_init, (uint64_t)flags, (uint64_t)event_f_flags); } 
static inline int32_t fanotify_mark(int32_t fanotify_fd, uint32_t flags, uint64_t mask, int32_t dirfd, const int8_t* pathname) { return (int32_t)syscall5(syscall_fanotify_mark, (uint64_t)fanotify_fd, (uint64_t)flags, (uint64_t)mask, (uint64_t)dirfd, (uint64_t)pathname); } 
static inline int32_t prlimit64(int32_t pid, int32_t resource, const void** new_limit, void** old_limit) { return (int32_t)syscall4(syscall_prlimit64, (uint64_t)pid, (uint64_t)resource, (uint64_t)new_limit, (uint64_t)old_limit); } 
static inline int32_t name_to_handle_at(int32_t dirfd, const int8_t* pathname, void** handle, int32_t* mount_id, int32_t flags) { return (int32_t)syscall5(syscall_name_to_handle_at, (uint64_t)dirfd, (uint64_t)pathname, (uint64_t)handle, (uint64_t)mount_id, (uint64_t)flags); } 
static inline int32_t open_by_handle_at(int32_t mount_fd, void** handle, int32_t flags) { return (int32_t)syscall3(syscall_open_by_handle_at, (uint64_t)mount_fd, (uint64_t)handle, (uint64_t)flags); } 
/* clock_adjtime parse error, omitted */
static inline int32_t syncfs(int32_t fd) { return (int32_t)syscall1(syscall_syncfs, (uint64_t)fd); } 
static inline int32_t sendmmsg(int32_t sockfd, void** msgvec, uint32_t vlen, int32_t flags) { return (int32_t)syscall4(syscall_sendmmsg, (uint64_t)sockfd, (uint64_t)msgvec, (uint64_t)vlen, (uint64_t)flags); } 
static inline int32_t setns(int32_t fd, int32_t nstype) { return (int32_t)syscall2(syscall_setns, (uint64_t)fd, (uint64_t)nstype); } 
static inline int32_t getcpu(uint32_t* cpu, uint32_t* node, void** tcache) { return (int32_t)syscall3(syscall_getcpu, (uint64_t)cpu, (uint64_t)node, (uint64_t)tcache); } 
static inline int64_t process_vm_readv(int32_t pid, const void** local_iov, uint64_t liovcnt, const void** remote_iov, uint64_t riovcnt, uint64_t flags) { return (int64_t)syscall6(syscall_process_vm_readv, (uint64_t)pid, (uint64_t)local_iov, (uint64_t)liovcnt, (uint64_t)remote_iov, (uint64_t)riovcnt, (uint64_t)flags); } 
static inline int64_t process_vm_writev(int32_t pid, const void** local_iov, uint64_t liovcnt, const void** remote_iov, uint64_t riovcnt, uint64_t flags) { return (int64_t)syscall6(syscall_process_vm_writev, (uint64_t)pid, (uint64_t)local_iov, (uint64_t)liovcnt, (uint64_t)remote_iov, (uint64_t)riovcnt, (uint64_t)flags); } 
static inline int32_t kcmp(int32_t pid1, int32_t pid2, int32_t type, uint64_t idx1, uint64_t idx2) { return (int32_t)syscall5(syscall_kcmp, (uint64_t)pid1, (uint64_t)pid2, (uint64_t)type, (uint64_t)idx1, (uint64_t)idx2); } 
static inline int32_t finit_module(int32_t fd, const int8_t* param_values, int32_t flags) { return (int32_t)syscall3(syscall_finit_module, (uint64_t)fd, (uint64_t)param_values, (uint64_t)flags); } 
static inline int32_t sched_setattr(int32_t pid, void** attr, uint32_t flags) { return (int32_t)syscall3(syscall_sched_setattr, (uint64_t)pid, (uint64_t)attr, (uint64_t)flags); } 
static inline int32_t sched_getattr(int32_t pid, void** attr, uint32_t size, uint32_t flags) { return (int32_t)syscall4(syscall_sched_getattr, (uint64_t)pid, (uint64_t)attr, (uint64_t)size, (uint64_t)flags); } 
static inline int32_t renameat2(int32_t olddirfd, const int8_t* oldpath, int32_t newdirfd, const int8_t* newpath, uint32_t flags) { return (int32_t)syscall5(syscall_renameat2, (uint64_t)olddirfd, (uint64_t)oldpath, (uint64_t)newdirfd, (uint64_t)newpath, (uint64_t)flags); } 
static inline int32_t seccomp(uint32_t operation, uint32_t flags, void* args) { return (int32_t)syscall3(syscall_seccomp, (uint64_t)operation, (uint64_t)flags, (uint64_t)args); } 
static inline int64_t getrandom(void* buf, uint64_t buflen, uint32_t flags) { return (int64_t)syscall3(syscall_getrandom, (uint64_t)buf, (uint64_t)buflen, (uint64_t)flags); } 
static inline int32_t memfd_create(const int8_t* name, uint32_t flags) { return (int32_t)syscall2(syscall_memfd_create, (uint64_t)name, (uint64_t)flags); } 
static inline int64_t kexec_file_load(int32_t kernel_fd, int32_t initrd_fd, uint64_t cmdline_len, const int8_t* cmdline, uint64_t flags) { return (int64_t)syscall5(syscall_kexec_file_load, (uint64_t)kernel_fd, (uint64_t)initrd_fd, (uint64_t)cmdline_len, (uint64_t)cmdline, (uint64_t)flags); } 
static inline int32_t bpf(int32_t cmd, void** attr, uint32_t size) { return (int32_t)syscall3(syscall_bpf, (uint64_t)cmd, (uint64_t)attr, (uint64_t)size); } 
static inline int32_t execveat(int32_t dirfd, const int8_t* pathname, const int8_t* argv, const int8_t* envp, int32_t flags) { return (int32_t)syscall5(syscall_execveat, (uint64_t)dirfd, (uint64_t)pathname, (uint64_t)argv, (uint64_t)envp, (uint64_t)flags); } 
static inline int32_t userfaultfd(int32_t flags) { return (int32_t)syscall1(syscall_userfaultfd, (uint64_t)flags); } 
static inline int32_t membarrier(int32_t cmd, int32_t flags) { return (int32_t)syscall2(syscall_membarrier, (uint64_t)cmd, (uint64_t)flags); } 
static inline int32_t mlock2(const void* addr, uint64_t len, int32_t flags) { return (int32_t)syscall3(syscall_mlock2, (uint64_t)addr, (uint64_t)len, (uint64_t)flags); } 
static inline int64_t copy_file_range(int32_t fd_in, int64_t* off_in, int32_t fd_out, int64_t* off_out, uint64_t len, uint32_t flags) { return (int64_t)syscall6(syscall_copy_file_range, (uint64_t)fd_in, (uint64_t)off_in, (uint64_t)fd_out, (uint64_t)off_out, (uint64_t)len, (uint64_t)flags); } 
static inline int64_t preadv2(int32_t fd, const void** iov, int32_t iovcnt, int64_t offset, int32_t flags) { return (int64_t)syscall5(syscall_preadv2, (uint64_t)fd, (uint64_t)iov, (uint64_t)iovcnt, (uint64_t)offset, (uint64_t)flags); } 
static inline int64_t pwritev2(int32_t fd, const void** iov, int32_t iovcnt, int64_t offset, int32_t flags) { return (int64_t)syscall5(syscall_pwritev2, (uint64_t)fd, (uint64_t)iov, (uint64_t)iovcnt, (uint64_t)offset, (uint64_t)flags); } 
static inline int32_t pkey_mprotect(void* addr, uint64_t len, int32_t prot, int32_t pkey) { return (int32_t)syscall4(syscall_pkey_mprotect, (uint64_t)addr, (uint64_t)len, (uint64_t)prot, (uint64_t)pkey); } 
static inline int32_t pkey_alloc(uint32_t flags, uint32_t access_rights) { return (int32_t)syscall2(syscall_pkey_alloc, (uint64_t)flags, (uint64_t)access_rights); } 
static inline int32_t pkey_free(int32_t pkey) { return (int32_t)syscall1(syscall_pkey_free, (uint64_t)pkey); } 
static inline int32_t statx(int32_t dirfd, const int8_t* pathname, int32_t flags, uint32_t mask, void** statxbuf) { return (int32_t)syscall5(syscall_statx, (uint64_t)dirfd, (uint64_t)pathname, (uint64_t)flags, (uint64_t)mask, (uint64_t)statxbuf); } 
/* io_pgetevents parse error, omitted */
/* rseq parse error, omitted */
static inline int32_t pidfd_send_signal(int32_t pidfd, int32_t sig, void** info, uint32_t flags) { return (int32_t)syscall4(syscall_pidfd_send_signal, (uint64_t)pidfd, (uint64_t)sig, (uint64_t)info, (uint64_t)flags); } 
/* io_uring_setup parse error, omitted */
/* io_uring_enter parse error, omitted */
/* io_uring_register parse error, omitted */
/* open_tree parse error, omitted */
/* move_mount parse error, omitted */
/* fsopen parse error, omitted */
/* fsconfig parse error, omitted */
/* fsmount parse error, omitted */
/* fspick parse error, omitted */
static inline int32_t pidfd_open(int32_t pid, uint32_t flags) { return (int32_t)syscall2(syscall_pidfd_open, (uint64_t)pid, (uint64_t)flags); } 
static inline int64_t clone3(void** cl_args, uint64_t size) { return (int64_t)syscall2(syscall_clone3, (uint64_t)cl_args, (uint64_t)size); }