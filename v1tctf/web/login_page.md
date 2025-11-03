# Challenge: Login Page
- Category: Web

## Description
<img width="623" height="421" alt="image" src="https://github.com/user-attachments/assets/a0428480-4e96-4960-b2de-1933a37427b1" />


## Flag: 
`v1t{p4ssw0rd}`

## Solution
Opening the page opened 2 dialog boxes asking for a username and password, rest of the page was just blank

so i checked view-source and got 
```html

<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>Login Panel</title>
</head>
<body>
  <script>
    async function toHex(buffer) {
      const bytes = new Uint8Array(buffer);
      let hex = '';
      for (let i = 0; i < bytes.length; i++) {
        hex += bytes[i].toString(16).padStart(2, '0');
      }
      return hex;
    }

    async function sha256Hex(str) {
      const enc = new TextEncoder();
      const data = enc.encode(str);
      const digest = await crypto.subtle.digest('SHA-256', data);
      return toHex(digest);
    }

    function timingSafeEqualHex(a, b) {
      if (a.length !== b.length) return false;
      let diff = 0;
      for (let i = 0; i < a.length; i++) {
        diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
      }
      return diff === 0;
    }

    (async () => {
      const ajnsdjkamsf = 'ba773c013e5c07e8831bdb2f1cee06f349ea1da550ef4766f5e7f7ec842d836e'; // replace
      const lanfffiewnu = '48d2a5bbcf422ccd1b69e2a82fb90bafb52384953e77e304bef856084be052b6'; // replace

      const username = prompt('Enter username:');
      const password = prompt('Enter password:');

      if (username === null || password === null) {
        alert('Missing username or password');
        return;
      }

      const uHash = await sha256Hex(username);
      const pHash = await sha256Hex(password);

      if (timingSafeEqualHex(uHash, ajnsdjkamsf) && timingSafeEqualHex(pHash, lanfffiewnu)) {
        alert(username+ '{'+password+'}');
      } else {
        alert('Invalid credentials');
      }
    })();
  </script>
</body>
</html>
```

Here the passwords are stored as sha256 hashes, so i used the tool at `https://10015.io/tools/sha256-encrypt-decrypt` to decrypt the username and password hashes which came out to be
Username: `v1t` and Password: `p4ssw0rd`. 

Entering the login creds gave me the flag

<img width="559" height="171" alt="image" src="https://github.com/user-attachments/assets/71725d7a-6d90-4191-a39d-29d1fcb0c47a" />




