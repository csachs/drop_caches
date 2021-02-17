// gcc drop_caches-noglibcsmall.c -nostdlib -Qn -Os  -Wl,--build-id=none -o drop_caches && strip -s -R .note.gnu.property -R .note.gnu.build-id -R .gnu.hash -R .comment  -R .eh_frame -R .eh_frame_hdr drop_caches

#include "syscalls.h"

void _start() {

    const char three = '3';
    const char pathname[] = "/proc/sys/vm/drop_caches";

    int file = open(pathname, 1);
    write(file, &three, 1);

    close(file);

    exit(0);

}
