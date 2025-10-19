# Challenge: More SQLi
- Category: Web

## Files and Setup
`http://saturn.picoctf.net:60277/`
## Flag: 
`picoCTF{G3tting_5QL_1nJ3c7I0N_l1k3_y0u_sh0ulD_98236ce6}`

## Solution
On opening the website, i saw a form which asked for my username and password, upon entering my details it showed 

<img width="674" height="68" alt="image" src="https://github.com/user-attachments/assets/de8a7099-c90c-449e-a9a6-c52d4cd98df5" />

So i just used `' OR 1=1; - //` basically setting username and pwd to always true, this logging me in.

<img width="995" height="837" alt="image" src="https://github.com/user-attachments/assets/c1547599-6dc7-4bfa-b729-997fa1ae00ca" />

In the search bar for cities, I ran `' UNION SELECT name, sql, null from sqlite_master;--` to figure out which table contains the flag,
This gave me the table more_table, 

<img width="810" height="752" alt="image" src="https://github.com/user-attachments/assets/d1212f8b-5be4-4f1e-a7c8-1fe343469740" />

After this, i ran `' UNION SELECT flag, null, null from more_table;--` and got the flag

<img width="867" height="544" alt="image" src="https://github.com/user-attachments/assets/27172c59-b146-4e54-8b48-789e1dfba607" />

