#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/fcntl.h>

#define PATH "/tmp/test_unlink.tmp"

int main(void) {
    int fd = open(PATH, O_CREAT | O_TRUNC | O_WRONLY, S_IRWXU);
    if (fd < 0) {
        perror("open failed");
        return EXIT_FAILURE;
    }
    if (close(fd) < 0) {
        perror("close failed");
        return EXIT_FAILURE;
    }
    if (unlink(PATH) < 0) {
        perror("unlink failed");
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
