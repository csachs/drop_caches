// curl https://chromium.googlesource.com/linux-syscall-support/+archive/refs/heads/main.tar.gz | tar xzf - linux_syscall_support.h
// gcc drop_caches-noglibclarge.c -nostdlib -Qn -Os  -Wl,--build-id=none -o drop_caches && strip -s -R .note.gnu.property -R .note.gnu.build-id -R .gnu.hash -R .comment  -R .eh_frame -R .eh_frame_hdr drop_caches

#include "linux_syscall_support.h"
#define open(a, b) sys_open(a, b, 0)
#define write sys_write
#define close sys_close
#define exit sys__exit

int __errno;
int *__errno_location (void) { return &__errno; }


void _start() {

    const char three = '3';
    const char pathname[] = "/proc/sys/vm/drop_caches";

    int file = open(pathname, 1);
    write(file, &three, 1);

    close(file);

    exit(0);

}
