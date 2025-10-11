# Challenge: Disk, disk, sleuth! II
- Category: Forensics

## Description
All we know is the file with the flag is named `down-at-the-bottom.txt`... Disk image: `dds2-alpine.flag.img.gz`

## Flag: 
`picoCTF{f0r3ns1c4t0r_n0v1c3_0d9d9ecb}`

## Solution
Since, the chall name mentions "sleuth", i knew that i had to use sluethkit in this question.

I ran `mmls dds2-alpine.flag.img` and got the output as:

<img width="1175" height="251" alt="image" src="https://github.com/user-attachments/assets/e87a8707-df26-4585-a816-4809b485d13f" />

which tells me that the linux partition begins at 2048. Thus i ran `fls -r -p -o 2048 dds2-alpine.flag.img | grep down-at-the-bottom.txt`

<img width="1470" height="102" alt="image" src="https://github.com/user-attachments/assets/2b26ce90-0432-47b6-a10f-0df2bc08463f" />

So, i now know that the inode number for the file is `18291`, which led me to run `icat -o 2048 dds2-alpine.flag.img 18291` to get the flag.

<img width="1388" height="343" alt="image" src="https://github.com/user-attachments/assets/13c34c8a-ffd3-41b9-b8f6-ceca43b4af95" />

## Resources Used
- http://wiki.sleuthkit.org/index.php?title=TSK_Tool_Overview
- https://www.sleuthkit.org/sleuthkit/man/fls.html

<img width="1919" height="775" alt="image" src="https://github.com/user-attachments/assets/e9fea94e-de77-4e6c-88e1-130d65349cd4" />
