#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/fcntl.h>

#define PATH "/dev/null"

const char *buf = "Hello World!";

int main(void) {
    int fd = open(PATH, O_WRONLY);
    if (fd < 0) {
        perror("open failed");
        return EXIT_FAILURE;
    }
    if (write(fd, buf, strlen(buf)) < 0) {
        perror("write failed");
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
