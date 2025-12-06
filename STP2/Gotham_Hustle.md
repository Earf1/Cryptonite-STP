# Challenge: Gotham Hustle
- Category: Forensics

## Description
Gotham’s underbelly trembles as whispers spread—The Riddler’s back, leaving cryptic puzzles across the city’s darkest corners. Every clue is a trap, every answer another step into madness. Think you can outsmart him? Step into Gotham’s shadows and prove it. Let the Batman's Hustle get its recognition!

I was given a file `gotham.raw`

## Flag: 


## Solution
I first ran `volatility -f ./gotham.raw imageinfo` to check the profile version to be used 
```
          Suggested Profile(s) : Win7SP1x64, Win7SP0x64, Win2008R2SP0x64, Win2008R2SP1x64_24000, Win2008R2SP1x64_23418, Win2008R2SP1x64, Win7SP1x64_24000, Win7SP1x64_23418
```
Im gonna move forward by using `Win7SP1x64`. 
Next as per routine, i checked the process list `volatility -f gotham.raw --profile=Win7SP1x64 pslist`

<img width="1208" height="903" alt="image" src="https://github.com/user-attachments/assets/3cacd464-5852-4aed-abd0-060c139b6f53" />

So theres notepad,paint,multiple chrome processes and conhost open.

First i just ran cmdscan `volatility -f gotham.raw --profile=Win7SP1x64 cmdscan` and got 

<img width="1582" height="416" alt="image" src="https://github.com/user-attachments/assets/f3ff65a4-4784-4aef-970b-a71b31fa92f4" />

Converting `Ymkwc2N0Znt3M2xjMG0zXw==` from b64 to ascii yields `bi0sctf{w3lc0m3_`, meaning this is a multi part challenge >:C. 
Other than this i also saw that the user had opened multiple instances of chrome, looking for how to check the history of a chrome instance, i found a plugin for vol2 called `chromehistory.py`, spent a lot of time trying to get ts to run but it just kept throwing errors at me be it a python2 runtime error or a volatility arg error, so i gave up on this route and decided to manually dump all the chrome processes and go through the search history myself

i ran 
` volatility -f gotham.raw --profile=Win7SP1x64_23418 pslist | grep -i chrome`, which gave me all the pids,

then i ran
`for pid in 4456 4432 4928 4872 4612 4204 3764 2608 3612 3172 3704 4452 4836 2168 3808 3740; do     volatility -f gotham.raw --profile=Win7SP1x64_23418 memdump -p $pid -D chrome_dumps; done` and then `strings chrome_dumps/* | grep -i flag`
with this i got a big ass output, which contained the link `https://www.google.com/search?q=flag3+%3D+aDBwM190aDE1Xw%3D%3D&aqs=chrome..69i57j0i512i546l2.321545j0j7&ie=UTF-8` 

got the 3rd flag as `h0p3_th15_`.

Now, moving onto the notepad process, i dumped all its data using `volatility -f test.raw --profile=Win7SP1x86_23418 memdump --dump-dir=./ -p 2592` and then ran strings on it to get `flag4 = YjNuM2YxNzVfeTB1Xw==` which decodes to `b3n3f175_y0u_`

Moving onto the paint process,


Finally, since there was activity on the desktop of bruce, i ran filescan and got a file called `flag5.rar`, but this file was password protected, so i ran strings on the rar file and got 
```
The password for the zip file is the computer's password...
```
so i ran `volatility -f gotham.raw --profile=Win7SP1x64 hashdump` from this i got the hash `b7265f8cc4f00b58f413076ead262720`

extracting the file i got flag.txt which contained `m0r3_13337431}`
<img width="1364" height="569" alt="image" src="https://github.com/user-attachments/assets/fe2dd552-1321-47c9-84d3-aaf78ef89867" />

