import sys
from pwn import *

context.arch = 'amd64'
context.bits = 64

arg_list = ''

if sys.argv.__len__() < 3:
    print("Usage : %s <elf> <argv0> [argv...]",file=sys.stderr)
    exit(1)
    
elf_file = sys.argv[1]

id = 0
for i in range(2,sys.argv.__len__()):
    argv = sys.argv[i]    
    arg_list += 'argv_{}:\n\t.ascii \"{}\"\n\t.byte 0x0\n'.format(id,argv)
    id += 1

arg_list += 'argv_{}:\n\t.byte 0x0\n'.format(id)
'''
elf_to_shellcode   elf   argv0,argv1,.....

objcopy -O binary -j .text ./execve ../elf_to_shellcode_amd64/loader_amd64

'''

'''

void x_execve(const char * file,int argc, const char * argv[],const char ** envp,long* sp,int load_from_mem)
'''

loader = ''

with open("./loader_amd64","rb") as f:
    for b in f.read():
        loader += '0x%02x,' % b
    loader = loader.rstrip(',')

with open(elf_file,"rb") as f:
    elf_data = f.read()

sc = '''
/*set args and argv*/
    xor rbp,rbp         /*argc*/
    
    lea rsi,[rip + argv_list]
    lea rdi,[rsp + 0x8]

__setup_argv:

    mov al,byte ptr [rsi]
    test al,al
    jz __setup_argv_ok

    mov [rdi],rsi       
    add rdi,0x8
    inc rbp
    
    /* go to next string. */   
_goto_next_argv:
    mov al,byte ptr [rsi]
    test al,al
    jz _goto_next_argv_ok
    inc rsi
    jmp _goto_next_argv
    
_goto_next_argv_ok:
    inc rsi
    
    jmp __setup_argv

    
__setup_argv_ok:
    lea rdi,[rip + elf]
    mov rsi,rbp
    mov [rsp],rbp
    
    lea rdx,[rsp + 0x8]
    
    xor rcx,rcx /*envp = NULL*/
    mov r8,rsp
    mov r9,0x1
    call x_execve

x_execve:
.byte {}

argv_list:
{}
    
elf:
'''.format(loader,arg_list)


#print(sc)
open("/proc/self/fd/1","wb").write(asm(sc) + elf_data)