# elf_to_shellcode

### Convert static linked elf , dynamic linked elf or command to shellcode.

### Supporter **architectures**

- amd64
- aarch64
- arm
- i386

### Usage:

```bash
python3 ./elf_to_shellcode_amd64.py elf argv[0] argv[1] ...
```

### Sample:

1. convert ls to shellcode 

```bash
python3 ./elf_to_shellcode_amd64.py /bin/ls /bin/ls ./>/tmp/shellcode
```

then run the shellcode :

```bash
root@LAPTOP-UFBOJERU:/elf_to_shellcode_amd64# ./run /tmp/shellcode
elf_to_shellcode_amd64.py  loader_amd64  run
```

2. convert busybox to shellcode 

```bash
python3 ./elf_to_shellcode_amd64.py /bin/busybox sh >/tmp/shellcode
```

run the shellcode:

```bash
root@LAPTOP-UFBOJERU:/elf_to_shellcode_amd64# ./run ./shellcode

BusyBox v1.30.1 (Ubuntu 1:1.30.1-4ubuntu6.4) built-in shell (ash)
Enter 'help' for a list of built-in commands.

/mnt/c/Users/lenovo/Desktop/elf_x_execve_mem/elf_to_shellcode_amd64 #
```
