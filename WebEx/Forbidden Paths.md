# Challenge: Forbidden Paths
- Category: Web

## Description
Can you get the flag?
We know that the website files live in /usr/share/nginx/html/ and the flag is at /flag.txt but the website is filtering absolute file paths. Can you get past the filter to read the flag?
Here's the website.

## Flag: 
`picoCTF{7h3_p47h_70_5ucc355_e5fe3d4d}`

## Solution
Since, the website files live in `/usr/share/nginx/html/` and absolute file paths were blocked, i used `../../../../flag.txt` to move up 4 directories (as given in the website path) to the root basically and access the flag.txt

<img width="865" height="268" alt="image" src="https://github.com/user-attachments/assets/d652c3b5-e0d2-408a-b248-5996ff974483" />


