# Challenge: 3v@l
- Category: Web

## Description
`ABC Bank's website has a loan calculator to help its clients calculate the amount they pay if they take a loan from the bank. Unfortunately, they are using an eval function to calculate the loan. Bypassing this will give you Remote Code Execution (RCE). Can you exploit the bank's calculator and read the flag?
The website is running Here.`

## Flag: 
`picoCTF{D0nt_Use_Unsecure_f@nctions5e20166b}`

## Solution
Looking at the view-source, i find
```
Secure python_flask eval execution by 
        1.blocking malcious keyword like os,eval,exec,bind,connect,python,socket,ls,cat,shell,bind
        2.Implementing regex: r'0x[0-9A-Fa-f]+|\\u[0-9A-Fa-f]{4}|%[0-9A-Fa-f]{2}|\.[A-Za-z0-9]{1,3}\b|[\\\/]|\.\.'
```
which meant i have to bypass the regex without using the blacklisted cmds, to get to my flag. The regex blocked:
- hex codes
- url encoding
- unicode escapes
- path traversal
- file extensions

So, I used `open(''.join([chr(x) for x in [47, 102, 108, 97, 103, 46, 116, 120, 116]])).read()`

In this payload,
- `47,102,108,97,103,46,116,120,116` are the ascii values for /flag.txt
- `chr(x)` converts these values to chars
- `' 'join()` concatenates them into a single file path
- `open(...).read()`, reads the flag file

With this, I was able to get the flag.

<img width="641" height="246" alt="image" src="https://github.com/user-attachments/assets/52deb73b-0d6b-4127-a9b7-6032ae4d5ead" />




