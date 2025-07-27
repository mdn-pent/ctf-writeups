- - - 
created : 17-07-2025 

Tags : #easy  
- - - 
# Objective

[[Hacking]] the [[Website]] .
# Recon
## Nmap

We can use [[Nmap]] to scan the machine IP :

```
    80/tcp open http  
    2222/tcp open ssh
```
# Enumeration
## Gobuster

We can use [[Gobuster]] to enumerate directories :

```
    /Lo-Fi_music
```
# Exploit

For the [[Exploit]] visiting http://IP_TM/Lo-Fi_music and exploring the [[Source Code]] we can easily see that there's [[Local File Inclusion (LFI)]] vulnerability 

so trying `http://IP_TM/?page=../../../../../etc/passwd` we are in and with `http://10.10.48.222/?page=../../../flag.txt`

we have the [[Flag]].