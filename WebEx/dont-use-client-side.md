# Challenge: dont-use-client-side
- Category: Web

## Description
Can you break into this super secure portal? https://jupiter.challenges.picoctf.org/problem/37821/ (link) or http://jupiter.challenges.picoctf.org:37821

## Files and Setup
`https://jupiter.challenges.picoctf.org/problem/37821/`

## Flag: 
`picoCTF{no_clients_plz_1a3c89}`

## Solution
On opening the website all i saw was,
<img width="1919" height="492" alt="image" src="https://github.com/user-attachments/assets/ad2eb462-a4e6-40b3-ac54-7bf36d4df621" />

On going through the source code, i found 
```
  function verify() {
    checkpass = document.getElementById("pass").value;
    split = 4;
    if (checkpass.substring(0, split) == 'pico') {
      if (checkpass.substring(split*6, split*7) == 'a3c8') {
        if (checkpass.substring(split, split*2) == 'CTF{') {
         if (checkpass.substring(split*4, split*5) == 'ts_p') {
          if (checkpass.substring(split*3, split*4) == 'lien') {
            if (checkpass.substring(split*5, split*6) == 'lz_1') {
              if (checkpass.substring(split*2, split*3) == 'no_c') {
                if (checkpass.substring(split*7, split*8) == '9}') {
                  alert("Password Verified")
                  }
                }
              }
      
            }
          }
        }
      }
    }
    else {
      alert("Incorrect password");
    }
```
In this verify() function, the creds entered are first split into 4, ` split = 4;` and then looking further, I found the entire flag split up in the variou checkpass if conditions, I just had to rearrange it properly based on its split function.
## Lessons Learned
- Client-side JavaScript is disclosure: sensitive logic and even full flags can leak via functions like verify() that assemble secrets from substrings. 
- Using view-source on a webiste can help bring such vulnerabilities to light.

