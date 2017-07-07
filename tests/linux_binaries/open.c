#include <stdlib.h>
#include <stdio.h>
#include <sys/fcntl.h>

#define PATH "/proc/cpuinfo"

int main(void) {
    int fd = open(PATH, O_RDONLY);
    if (fd < 0) {
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
