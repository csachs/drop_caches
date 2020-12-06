/* gcc drop_caches.c -o drop_caches */
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {

    char str[] = {'3', '\n'};

    FILE *fp = fopen("/proc/sys/vm/drop_caches", "wb");

    fwrite(str, sizeof(char), sizeof(str), fp);

    fclose(fp);

    return 0;
}

