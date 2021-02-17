# gcc drop_caches-assembly.s -o drop_caches -no-pie -Wl,--build-id=none -nostdlib && strip drop_caches

.section .data

_filename:
    .string "/proc/sys/vm/drop_caches"
.equ _filename_len, . - _filename

_three:
    .ascii "3"
.equ _three_len, . - _three

.section .text

.globl _start
_start:

# open
    mov $2, %rax
    lea _filename, %rdi
    mov $1, %rsi
    syscall

# store file handle in %r15
    mov %rax, %r15

# write
    mov $1, %rax
    mov %r15, %rdi
    lea _three, %rsi
    mov $_three_len, %rdx
    syscall

# close
    mov $3, %rax
    mov %r15, %rdi
    syscall

# call exit
    mov $60, %rax
    xor %rdi, %rdi
    syscall

# syscall syntax
# # %rax = syscall_%rax ( %rdi, %rsi, %rdx, %r10, %r8, %r9 )
