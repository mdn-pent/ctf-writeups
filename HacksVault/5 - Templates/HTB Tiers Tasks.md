- - - 
created : 30-07-2025 

Tags : #veryeasy
- - - 
# Objective

Learn how to start.
# CONNECT

To attack the target machine, you must be on the same network.  
Connect to the Starting Point VPN using one of the following options.

It may take a minute for HTB to recognize your connection.  
If you don't see an update after 2-3 minutes, refresh the page.

I will use OpenVPN, so i download the config file, go in the same directory and execute the following command :

```bash
┌──(mdn0x㉿mdn0xKali)-[~/HTB]
└─$ sudo openvpn starting_point_mdn0x.ovpn 
[sudo] password di mdn0x: 
```

We can start our [Vulnerable Machine](../3%20-%20Tags/Hacking%20Concepts/Vulnerable%20Machine.md).

Now we add the target IP to our /etc/hosts file, so we don't have to remember the [IP address](../3%20-%20Tags/Hacking%20Concepts/IP%20address.md) every time :

```bash
┌──(mdn0x㉿mdn0xKali)-[~/HTB/Starting Point/Tier 0/Meow]
└─$ sudo nano /etc/hosts
```

We add a line with the given IP and a name .
# Task 1

Which TCP port is open on the machine?
## Rustscan/Nmap

We can use [Rustscan](../3%20-%20Tags/Hacking%20Tools/Rustscan.md) that will pass the result to [Nmap](../3%20-%20Tags/Hacking%20Tools/Nmap.md) :

```bash
 ┌──(mdn0x㉿mdn0xKali)-[~/HTB/Starting Point/Tier 0/Reedemer]
└─$ rustscan 

```
# Task 2

Which TCP port is open on the machine?

```bash
 
```
# Task 3

What type of database is Redis? Choose from the following options: (i) In-memory Database, (ii) Traditional Database

```bash
  
```
# Task 4

Which command-line utility is used to interact with the Redis server? Enter the program name you would enter into the terminal without any arguments.

```bash
 
```
# Task 5

Which flag is used with the Redis command-line utility to specify the hostname?

```bash
 
```
# Task 6

Once connected to a Redis server, which command is used to obtain the information and statistics about the Redis server?

```bash
 
```
# Task 7

What is the version of the Redis server being used on the target machine?

```bash

```
# Task 8

Which command is used to select the desired database in Redis?

```bash
 
```
# Task 9

How many keys are present inside the database with index 0?
# Task 10

Which command is used to obtain all the keys in a database?

```bash
  
```
# Task 11

Submit root flag

