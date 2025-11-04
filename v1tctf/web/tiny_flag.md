# Challenge: Tiny Flag
- Category: Web

## Description

<img width="653" height="446" alt="image" src="https://github.com/user-attachments/assets/a8af5ba0-6c6b-461d-9c68-e234e7fece58" />

## Flag: 
`V1T{T1NY_ICO}`

## Solution
The webpage looked like 

<img width="1916" height="867" alt="image" src="https://github.com/user-attachments/assets/31c5e1cf-50e0-44bc-a4c8-d956b476d23b" />

Looking at the source code, the header block was
```html
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>Tiny flag — Fancy</title>
  <link rel="shortcut icon" href="favicon.ico" type="image/x-icon">
  <link rel="stylesheet" href="data:text/css,.faux{display:block;} .hint{font-size:12px;color:rgba(255,255,255,0.3)}">
    <link rel="stylesheet" href="style.css">
</head>
```
Going to `favicon.ico` just gave me the flag

<img width="238" height="222" alt="image" src="https://github.com/user-attachments/assets/ba45c39d-c6f8-4536-9be2-3dc6dcd01682" />
