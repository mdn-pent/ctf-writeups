- - - 
created : 17-07-2025 

Tags : #easy  
- - - 
# Exploit
## Netcat

the room says that we can do it so we straightly use [[Netcat]] :

```
nc IP -p 1337
This XOR encoded text has flag 1: 0304790937662d581c331234403333237857192416224641263b004d1a1225384d423225347b003a
```

We have a [[XOR]] encoded flag so we have to [[Decipher]] it
## CyberChef

we are gonna use [[CyberChef]] to decrypt the [[XOR]] flag , after examining the [[Source Code]], we get to know a couple of details that will help us recover the key and decipher the encrypted  [[Flag]]: - the XOR key has a length of 5.  
                                                         - Second, the flag has the format of THM{...}

When we try the message with the encryption key **8ndEw** we get the first  [[Flag]]. 

We can access by netcat using **8ndEw** ([[Encryption key]]) . 