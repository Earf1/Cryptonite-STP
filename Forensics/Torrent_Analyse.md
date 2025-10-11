# Challenge: Torrent Analyse
- Category: Forensics

## Description
SOS, someone is torrenting on our network.
One of your colleagues has been using torrent to download some files on the company’s network. Can you identify the file(s) that were downloaded? The file name will be the flag, like picoCTF{filename}

## Flag: 
`picoCTF{ubuntu-19.10-desktop-amd64.iso}`

## Solution
On analysing the .pcap file, i find multiple protocols present, but since the challenge talks about torrents, I focus on `BT-DHT` exchanges. 
Going through these, i find multiple info-hashes with multiple sources, but since have to find out the file that was downloaded, i only focused on the info-hashes with `src=192.168.73.132` 

<img width="1452" height="709" alt="image" src="https://github.com/user-attachments/assets/b715fd9f-9ce5-42e1-b62b-dc6d5796359e" />

Since, all of these hashes are the same, i looked it up on google and got the file name as `ubuntu-19.10-desktop-amd64.iso`.
