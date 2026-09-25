/* A cat for the macOS name checks, which need a program of their own: macOS kills a copy of one
 * of its programs, such as /bin/cat, as it starts. */
#include <unistd.h>

int main(void) {
    char buf[4096];
    ssize_t n;
    while ((n = read(0, buf, sizeof buf)) > 0)
        write(1, buf, (size_t)n);
    return 0;
}
