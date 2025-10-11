# Challenge: Intro To Burp
- Category: Web

## Files and Setup
We were given a link `http://titan.picoctf.net:56929/`

## Flag: 
` picoCTF{#0TP_Bypvss_SuCc3$S_c94b61ac}`

## Solution
We were given a website, with a form which asked for name and other details, i filled random details in these, and it led me to a page which asked for an otp

<img width="735" height="279" alt="image" src="https://github.com/user-attachments/assets/dddd9034-ebb0-4f01-8dcf-98386639df70" />

I used Burp Suite in proxy mode to intercept the submission of the otp, and found this 

<img width="652" height="292" alt="image" src="https://github.com/user-attachments/assets/04ba495b-d96a-463b-a44b-85778d99de22" />

I proceeded to remove the otp request completely, and forwarded the request, this led me to the flag.


## Lessons Learned
- Using BurpSuite in proxy mode 
- Removing the otp parameter showed the backend did not enforce server side validation


