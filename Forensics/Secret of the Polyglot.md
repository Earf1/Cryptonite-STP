# Challenge: Secret of the Polyglot
- Category: Forensics

## Description
The Network Operations Center (NOC) of your local institution picked up a suspicious file, they're getting conflicting information on what type of file it is. They've brought you in as an external expert to examine the file. Can you extract all the information from this strange file?
Download the suspicious file here.

## Flag: 
`picoCTF{f1u3n7_1n_pn9_&_pdf_724b1287}`

## Solution
This is a pretty straightforward challenge, we are given a .pdf file, which has half the flag in it `1n_pn9_&_pdf_724b1287}`, now in this flag it mentioned png, and running strings on it confirmed that since an IHDR and IDAT chunk is present

<img width="1441" height="699" alt="image" src="https://github.com/user-attachments/assets/301a6577-d33d-4f9f-8a8c-0f5396cb2d76" />

So i changed the file extension to .png, which gave me the other half 

<img width="50" height="50" alt="flag2of2-final" src="https://github.com/user-attachments/assets/2ecc2ce3-bf70-45d2-bed1-e7b0822b2dde" />
