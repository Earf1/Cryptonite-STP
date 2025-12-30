# Challenge: chal 1 
- Category: Web  

## Flag:  
`flag{fakeflag}`  

## Solution  

looking at the src code i found that the website hosts the flag at `/uploads/flag.txt`,

however, when attempting to access that path via `/uploads/flag.txt`, i got a **403 Forbidden** 
Looking at the provided Dockerfile, this makes sense:  

```
RUN chmod 000 /var/www/html/uploads/flag.txt
```

The flag file initially has no read permissions at all

Inspecting`index.php`, i saw the following logic executed upon upload:  

```php
if (isset($_FILES['file'])) {
  $target_dir = "/var/www/html/uploads/";
  $target_file = $target_dir . basename($_FILES["file"]["name"]);

  if (!str_ends_with($target_file, '.txt')) {
    echo "You can only upload .txt files!";
    $uploadOk = 0;
  }

  if ($uploadOk) {
    move_uploaded_file($_FILES["file"]["tmp_name"], $target_file);
  }

  chdir($target_dir);
  shell_exec('chmod 000 *');  // <== Critical line
  chdir($old_path);
}
```

The vulnerability lies in this `shell_exec('chmod 000 *');`.  
The asterisk `*` is expanded by the shell, meaning that any uploaded file name will be parsed as an argument to `chmod`, instead of being considered a file.
For example:  
```
chmod 000 flag.txt file1.txt file2.txt
```

So if i upload a file whose name starts with a dash (`-`), it will be treated as a command-line option

The `chmod` command has an option called `--reference=<file>`, which applies the same permissions of a reference file to other files,

- so i uploaded a file called `--reference=abc.txt`, which a file whose name is interpreted as the flag for `chmod`, not a normal file.  
- then i uploaded another file named `abc.txt`, now this file gets uploaded normally and has default readable permissions.  
- now thehe next time `chmod 000 *` runs, the expanded command looks like this:  
     ```
     chmod 000 flag.txt --reference=abc.txt abc.txt
     ```
  Here, `chmod` copies the permissions from `abc.txt` onto `flag.txt`, effectively restoring read access.

Now, i just visited `http://localhost:8080/uploads/flag.txt` and got the flag

### Mitigation  

Argument injections can occur if filenames are directly interpolated in shell commands. Always quote or sanitize user-supplied file names before executing system calls like `chmod`, `mv`, `ls`, etc.
