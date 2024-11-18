import sys
from pwn import *

context.arch = 'i386'
context.bits = 32

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

i686-linux-gnu-objcopy -O binary -j .text ./execve ../elf_to_shellcode_i386/loader_i386

'''

'''

void x_execve(const char * file,int argc, const char * argv[],const char ** envp,long* sp,int load_from_mem)
'''

loader = ''

with open("./loader_i386","rb") as f:
    for b in f.read():
        loader += '0x%02x,' % b
    loader = loader.rstrip(',')

with open(elf_file,"rb") as f:
    elf_data = f.read()


sc = '''
/*set args and argv*/
    xor ebp,ebp                      /*argc*/
    
    call _get_pc
___label_1_begin:
    mov esi,eax
    add esi,___label_1_end - ___label_1_begin
    lea edi,[esp + 0x4]

__setup_argv:
    mov al,byte ptr [esi]
    test al,al
    jz __setup_argv_ok

    mov [edi],esi       
    add edi,0x4
    inc ebp
    
    /* go to next string. */   
_goto_next_argv:
    mov al,byte ptr [esi]
    test al,al
    jz _goto_next_argv_ok
    inc esi
    jmp _goto_next_argv
    
_goto_next_argv_ok:
    inc esi
    jmp __setup_argv

    
__setup_argv_ok:

    mov [esp],ebp           /* setup argc */
    mov esi,ebp

    call _get_pc
___label_2_begin:
    mov edi,eax
    add edi,___label_2_end - ___label_2_begin

    lea edx,[esp + 0x4]
    xor ecx,ecx

    mov eax, esp

    push 0x1                /*    */
    push eax                /* sp */
    push ecx
    push edx
    push esi
    push edi

    call x_execve

_get_pc:
    mov eax,[esp]
    ret

.align 4
___label_1_end:
argv_list:
{}

.align 4
x_execve:
.byte {}

.align 4
___label_2_end:
elf:
'''.format(arg_list,loader)
#print(sc)

#print(len(loader)//5)
open("/proc/self/fd/1","wb").write(asm(sc) + elf_data)

#print(asm(sc))