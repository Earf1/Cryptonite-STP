# Challenge: flag{key1+key2}
- Category: RevEng

## Description


## Flag: 
`flag{456789+JKLq59U1337}`

## Solution
Running strings on it i got 
```
$Info: This file is packed with the UPX executable packer http://upx.sf.net $
$Id: UPX 3.91 Copyright (C) 1996-2013 the UPX Team. All Rights Reserved. $
PROT_EXEC|PROT_WRITE failed.
```

So i used upx to unpack the binary

Running the binary gave me
```
advay@DESKTOP-MASF3ES:/mnt/c/Users/advay/Desktop/cryptonite/Revchalls-main$ ./flag
Oops wrong path
Oops wrong path
```
```
08061fff    int32_t main__one()

08061fff    {
08061fff        void* gsbase;
08062005        int32_t eax = *(uint32_t*)((char*)gsbase + 0x14);
08062010        int32_t var_1c = 0xfffffffe;
08062028        void var_4c;
08062028        __new_array_with_default(&var_4c, 6, 0, 4, &var_1c);
08062030        int32_t var_5c = 0x2d;
080620d4        int32_t var_14 = 0xfffffffd;
080620ec        int32_t var_2c;
080620ec        __new_array_with_default(&var_2c, 6, 0, 4, &var_14);
080620f4        char const* const var_3c = "You don't have the first part of key yet";
0806210c        int32_t var_74_2 = 1;
08062115        println(var_3c, 0x28);
08062121        int32_t result = eax ^ *(uint32_t*)((char*)gsbase + 0x14);
08062121        
08062128        if (!result)
08062130            return result;
08062130        
0806212a        __stack_chk_fail();
0806212a        /* no return */
08061fff    }


08062131    int32_t main__two()

08062131    {
08062131        void* gsbase;
0806213a        int32_t eax = *(uint32_t*)((char*)gsbase + 0x14);
08062145        int32_t var_98 = 0xfffffff9;
08062166        void var_d8;
08062166        __new_array_with_default(&var_d8, 7, 0, 4, &var_98);
0806216e        int32_t var_ec = 0x5a;
0806238c        int32_t result = eax ^ *(uint32_t*)((char*)gsbase + 0x14);
0806238c        
08062393        if (!result)
0806239b            return result;
0806239b        
08062395        __stack_chk_fail();
08062395        /* no return */

08062131    }
```

I further looked at these in disassembly instead of psuedo-c and from `main_two()` i got `JKLq59U137 ` which is the 2nd part of the flag.

Now, looking back at `main_one()` and `main_main()` in assembly,

<img width="838" height="307" alt="image" src="https://github.com/user-attachments/assets/0b421e1d-f11d-42ca-982e-309c9187a953" />

Here, `0x17` is moved to `ebp+var_28` and then compared with `0x2d`, and then calls `main_one()`. since they are never equal, the function `main_one()` is never called.
So, i patched it from `jne` to `je` and ran the patched file

<img width="808" height="176" alt="image" src="https://github.com/user-attachments/assets/7488e343-cf13-403c-8519-e00c442df11b" />

Running the patched file, gave me 
```
advay@DESKTOP-MASF3ES:/mnt/c/Users/advay/Desktop/cryptonite/Revchalls-main$ ./flag_patched
You don't have the first part of key yet
Oops wrong path
```
Which meant that the `main_one()` function is now being called. Looking into `main_one()` now, i saw that the comparision is happening with `0x1f`, which will always be false, so instead of `0x1f` i changed it to `0x6f`.

<img width="728" height="121" alt="image" src="https://github.com/user-attachments/assets/1a342dc0-e4ad-4b96-bdd2-906cad446bab" />

Running the patched binary now gave me
```
advay@DESKTOP-MASF3ES:/mnt/c/Users/advay/Desktop/cryptonite/Revchalls-main$ ./flag_patched
[4, 5, 6, 7, 8, 9]
Oops wrong path
```
This gave me the first part of the flag which is `456789`
