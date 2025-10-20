# Challenge: minesweeper
- Category: RevEng

## Description
I was given `net.exe` which upon opening was a minesweeper game

<img width="806" height="988" alt="image" src="https://github.com/user-attachments/assets/f0a36bc9-fb9a-4dbe-b5ea-774bf2489df2" />

## Flag: 
`Ch3aters_Alw4ys_W1n@flare-on.com`

## Solution
Since the file was a net binary, i opened it in dnspy (had to look up net binary decompilers since ghidra and binary ninja were failing to do it properly)

<img width="646" height="620" alt="image" src="https://github.com/user-attachments/assets/3b5f4c99-1304-4136-9298-55ba7339c399" />

Looking at the `MainForm` function, 

<img width="775" height="469" alt="image" src="https://github.com/user-attachments/assets/4aa97272-62e8-40c3-a7ca-15b5659c2e1e" />

Here, i first looked at `InitialiseComponent` to see if maybe the flag was hidden there, but i didnt find anything
Moving on to `AllocateMemory`, i saw that the 2 loops are from 0 to 30, which means that the board is `30x30`. 

<img width="802" height="380" alt="image" src="https://github.com/user-attachments/assets/2a7a1f6d-c469-43b4-a333-42904eaee19b" />

Seeing GarbageCollect=flag made me look at that array and i found 

<img width="794" height="273" alt="image" src="https://github.com/user-attachments/assets/04809795-d39f-4f6b-9296-cc17108951aa" />

The minesPresent part can help me in getting all the mines present, so i went ahead with setting a breakpoint on `flag=flase` but it was too much of bruteforcing as i had to basically check all 900 boxes on my own.

Looking more into the other classes, i found `MineFieldControl` 

<img width="1103" height="676" alt="image" src="https://github.com/user-attachments/assets/7b6c7be1-77e6-44b9-a028-9c1ca9d82b74" />

First, it calculates the row and column position of the click and stores it in the variables num and num2 respectively
Then, it checks which mouse button was pressed and proceeds accordingly (i set a breakpoint here)

<img width="1010" height="239" alt="image" src="https://github.com/user-attachments/assets/f906b783-f699-4834-922e-a9e00e187b9f" />

This gave me the position of the first out of 3 non mine squares as `(28,7)` 
Running this 2 more times gave me the other positions as `(20,7)` and `(28,24)`

Now running it further opened the minesweeper board for me, I pressed on `(28,7)` , `(20,7)` and `(28,24)`.

This got me the flag

<img width="1018" height="655" alt="image" src="https://github.com/user-attachments/assets/0226536a-2423-4c98-b4ae-85906a3b397a" />


