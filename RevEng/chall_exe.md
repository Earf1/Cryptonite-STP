# Challenge: chall.exe
- Category: RevEng

## Description
I was just given `chal.exe` which upon launching would show

<img width="591" height="269" alt="image" src="https://github.com/user-attachments/assets/1e62d83c-c3b2-4908-8502-efc0c2acf19f" />


## Solution
Running `chall.exe` prompted for:
```
User ID: 
Password: 
```

So, i knew i had to find the credentials to get the flag.

Since, the file was small enough, i used `dogbolt` to decompile the file 
Going through the decompiled binary revealed:
- Anti-debugging checks to detect debuggers
- Custom Virtual Machine implementation using a bytecode interpreter (`sub_1400048e0`) for execution obfuscation

After analyzing the decompiled code, i found the key validation function `sub_140002d30` which handles the credential chjecking

lines 1133-1135 in the decompiled code, gave me the credentials

```c
int64_t var_20d0;
memset(&var_20d0, 0, 0x2098);
data_14000d740 = 0;
char i_11 = *arg1;
int64_t rcx_1;

// ... 

int64_t var_20da;
__builtin_strcpy(&var_20da, "panhauzer");
int64_t var_20e3;
__builtin_strncpy(&var_20e3, "2digboob", 9);
int32_t var_21ec;
__builtin_memset(&var_21ec, 0, 0x104);
```

The function `sub_140002d30` appears to be a validation call that takes two arguments (`arg1` for userId, `arg2` for password), compares them against the hardcoded values, and returns `1` (success) or `0` (failure) based on the comparison

Now, i ran `chall.exe` again and entered these credentials 

<img width="523" height="244" alt="image" src="https://github.com/user-attachments/assets/97c3d381-6e18-4845-8d2c-cbdf6d1e040a" />

Authentication complete = chall solved
