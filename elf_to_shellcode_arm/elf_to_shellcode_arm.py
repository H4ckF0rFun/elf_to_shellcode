import sys
from pwn import *

context.arch = 'arm'
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

arm-linux-gnueabi-objcopy -O binary -j .text ./execve ../elf_to_shellcode_arm/loader_arm

'''

'''

void x_execve(const char * file,int argc, const char * argv[],const char ** envp,long* sp,int load_from_mem)
'''

loader = ''

with open("./loader_arm","rb") as f:
    for b in f.read():
        loader += '0x%02x,' % b
    loader = loader.rstrip(',')

with open(elf_file,"rb") as f:
    elf_data = f.read()


sc = '''
/*set args and argv*/
    mov r4,0
    mov r0,0
    mov r5,argv_list - _label_1 - 4   /*手动计算..*/
    add r1,pc,r5
_label_1:
    add r2, sp, 0x4
    
__setup_argv:
    ldrb r0,[r1,0]
    cmp r0,0
    beq __setup_argv_ok

    str r1,[r2 , 0x0]
    
    add r2,r2,0x4
    add r4,r4,1
    
    /* go to next string. */   

_goto_next_argv:
    ldrb r0,[r1,0]
    cmp r0,0
    beq _goto_next_argv_ok
    add r1,r1,0x1
    b _goto_next_argv
    
_goto_next_argv_ok:
    add r1,r1,1  
    
    b __setup_argv

__setup_argv_ok:
    mov r5,elf - _label_2 - 0x4
    add r0,pc,r5
_label_2:
    mov r1,r4
    str r1,[sp,0]
    
    add r2, sp , 0x4
    
    mov r3,0
    
    mov r8,sp
    mov r9,0x1
    
    sub sp,sp,0x8
    str r8,[sp,0x0]
    str r9,[sp,0x4]
    
    bl  x_execve

.align 4
argv_list:
{}

.align 4
x_execve:
.byte {}

.align 4
elf:
'''.format(arg_list,loader)
#print(sc)

#print(len(loader)//5)
open("/proc/self/fd/1","wb").write(asm(sc) + elf_data)

#print(asm(sc))