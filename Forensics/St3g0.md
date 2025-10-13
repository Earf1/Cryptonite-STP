# Challenge: St3g0

- Category: Forensics

## Description
Download this image and find the flag.
`pico.flag.png`

## Flag:
`picoCTF{7h3r3_15_n0_5p00n_a1062667}`

## Solution
Running exiftool on it gave me 
```
advay@DESKTOP-MASF3ES:/mnt/c/Users/advay/Desktop/cryptonite/forensics$ exiftool pico.flag.png
ExifTool Version Number         : 12.76
File Name                       : pico.flag.png
Directory                       : .
File Size                       : 13 kB
File Modification Date/Time     : 2025:10:08 14:02:14+00:00
File Access Date/Time           : 2025:10:08 14:02:14+00:00
File Inode Change Date/Time     : 2025:10:08 14:21:57+00:00
File Permissions                : -rwxrwxrwx
File Type                       : PNG
File Type Extension             : png
MIME Type                       : image/png
Image Width                     : 585
Image Height                    : 172
Bit Depth                       : 8
Color Type                      : RGB with Alpha
Compression                     : Deflate/Inflate
Filter                          : Adaptive
Interlace                       : Noninterlaced
Image Size                      : 585x172
Megapixels                      : 0.101
```
Nothing found here, so i opened the image on `https://www.aperisolve.com/`, here in the zsteg section, I found the flag.

<img width="1698" height="413" alt="image" src="https://github.com/user-attachments/assets/d0f00bf4-87cf-40c3-aea1-99aee93ac817" />


## Resources

- https://www.aperisolve.com/
