# Challenge: Who are you?
- Category: Web

## Description
Let me in. Let me iiiiiiinnnnnnnnnnnnnnnnnnnn http://mercury.picoctf.net:38322/

## Flag: 
`picoCTF{http_h34d3rs_v3ry_c0Ol_much_w0w_b22d773c}`

## Solution
Upon opening the site, it shows,

<img width="1161" height="823" alt="image" src="https://github.com/user-attachments/assets/c4c6e15c-92f6-44a3-a30a-863ce8d3111e" />

So, I changed the UsrAgent to `PicoBrowser` after opening the website in BurpSuite.

Upon doing this, the site tells me that "I dont trust users from other websites"

<img width="1491" height="810" alt="image" src="https://github.com/user-attachments/assets/342e4b8b-2648-4bda-a6ef-73f46fbc6e60" />

So, I added a referer header `Referer: mercury.picoctf.net:38322`, adding the website as its own referer.

This gives me a msg saying, "Sorry this site only worked in 2018", So i added a date header `Date: Mon, 17 Sep 2018 12:34:56 GMT`

This led to the website telling me "I dont trust users who can be tracked".

So, I added a do not track header `DNT: 1`

This led to it telling me "The website is only for people from Sweden", so i changed the location and language to Sweden and Swedish, 
`Accept-Language: sv-sv,sv;q=0.5` and `X-Forwarded-For: 46.59.120.34`.

With all of these headers in place, i finally got the flag.

**Final Payload**
```
GET / HTTP/1.1
Host: mercury.picoctf.net:38322
Cache-Control: max-age=0
Accept-Language: sv-sv,sv;q=0.5
Upgrade-Insecure-Requests: 1
User-Agent: PicoBrowser
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate, br
Referer: mercury.picoctf.net:38322
Connection: keep-alive
Date: Mon, 17 Sep 2018 12:34:56 GMT
X-Forwarded-For: 46.59.120.34
DNT: 1
Content-Length: 3
```

## Resources
- https://datatracker.ietf.org/doc/html/rfc2616
