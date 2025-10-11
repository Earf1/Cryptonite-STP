# Challenge: Bitlocker 1
- Category: Forensics

## Description
Jacky is not very knowledgable about the best security passwords and used a simple password to encrypt their BitLocker drive. See if you can break through the encryption!
Download the disk image here

## Flag: 
`picoCTF{us3_b3tt3r_p4ssw0rd5_pl5!_3242adb1}`

## Solution
Running strings on the .dd file didnt lead to anything of substance, so i moved forward and looking at the question desc again, the mention of a password, led me to looking for password cracking tools for .dd files.
I got something called `bitlocker2john`

I ran `bitlocker2john -i bitlocker-1.dd > hash.txt`

<img width="1028" height="822" alt="image" src="https://github.com/user-attachments/assets/8fbe482a-6765-48c8-98de-1494917a732c" />

This is the output it gave me
```
Encrypted device bitlocker-1.dd opened, size 100MB
Salt: 2b71884a0ef66f0b9de049a82a39d15b
RP Nonce: 00be8a46ead6da0106000000
RP MAC: a28f1a60db3e3fe4049a821c3aea5e4b
RP VMK: a1957baea68cd29488c0f3f6efcd4689e43f8ba3120a33048b2ef2c9702e298e4c260743126ec8bd29bc6d58

UP Nonce: d04d9c58eed6da010a000000
UP MAC: 68156e51e53f0a01c076a32ba2b2999a
UP VMK: fffce8530fbe5d84b4c19ac71f6c79375b87d40c2d871ed2b7b5559d71ba31b6779c6f41412fd6869442d66d


User Password hash:
$bitlocker$0$16$cb4809fe9628471a411f8380e0f668db$1048576$12$d04d9c58eed6da010a000000$60$68156e51e53f0a01c076a32ba2b2999afffce8530fbe5d84b4c19ac71f6c79375b87d40c2d871ed2b7b5559d71ba31b6779c6f41412fd6869442d66d
Hash type: User Password with MAC verification (slower solution, no false positives)
$bitlocker$1$16$cb4809fe9628471a411f8380e0f668db$1048576$12$d04d9c58eed6da010a000000$60$68156e51e53f0a01c076a32ba2b2999afffce8530fbe5d84b4c19ac71f6c79375b87d40c2d871ed2b7b5559d71ba31b6779c6f41412fd6869442d66d
Hash type: Recovery Password fast attack
$bitlocker$2$16$2b71884a0ef66f0b9de049a82a39d15b$1048576$12$00be8a46ead6da0106000000$60$a28f1a60db3e3fe4049a821c3aea5e4ba1957baea68cd29488c0f3f6efcd4689e43f8ba3120a33048b2ef2c9702e298e4c260743126ec8bd29bc6d58
Hash type: Recovery Password with MAC verification (slower solution, no false positives)
$bitlocker$3$16$2b71884a0ef66f0b9de049a82a39d15b$1048576$12$00be8a46ead6da0106000000$60$a28f1a60db3e3fe4049a821c3aea5e4ba1957baea68cd29488c0f3f6efcd4689e43f8ba3120a33048b2ef2c9702e298e4c260743126ec8bd29bc6d58
```

Using the first hash, i first extracted the first 100000 passwords from rockyou into a dictionary.txt for faster usage by `head -n 100000 /usr/share/wordlists/rockyou.txt > dictionary.txt`
Then i ran `hashcat -m 22100 -a 0 hash.txt dictionary.txt` to crack the password. 

Within 5 minutes, i got

<img width="1919" height="61" alt="image" src="https://github.com/user-attachments/assets/6dd677f5-08c7-43c1-ba9d-ba6013f84328" />

Now with the password as jacqueline I had to actually extract the contents of the .dd file, I did this with a tool i found called dislocker, i ran `sudo dislocker bitlocker-1.dd -ujacqueline bitloader1`
With this i got the dislocker file, which i mounted using `sudo mount -o loop bitloader1/dislocker-file bitlocker1mount`

inside the mount, i found flag.txt 

<img width="1036" height="159" alt="image" src="https://github.com/user-attachments/assets/515c0131-2e9f-4a82-85b6-d4f7c7aab8cd" />

Reading that gave me the flag

<img width="1130" height="74" alt="image" src="https://github.com/user-attachments/assets/b0df6952-4e77-4c84-b074-553a992a02b6" />

## Resources:
- https://github.com/Aorimn/dislocker
- https://github.com/tuxera/ntfs-3g
