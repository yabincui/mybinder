#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <binder.h>

struct binder_state {
  int fd;
};

int main() {
  binder_state bs;
  bs.fd = open("/dev/binder", O_RDWR | O_CLOEXEC);
  if (bs.fd == -1) {
    fprintf(stderr, "open failed: %s\n", strerror(errno));
    exit(1);
  }
  char buf[100];
  while (true) {
    printf("exit (y/n)? ");
    fgets(buf, sizeof(buf), stdin);
    if (buf[0] == 'y') {
      break;
    }
  }
  close(bs.fd);
}
