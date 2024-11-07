import sys
from pwn import *

context.arch = 'aarch64'
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

aarch64-linux-gnu-objcopy -O binary -j .text ./execve ../elf_to_shellcode_aarch64/loader_aarch64

'''

'''

void x_execve(const char * file,int argc, const char * argv[],const char ** envp,long* sp,int load_from_mem)
'''

loader = ''

with open("./loader_aarch64","rb") as f:
    for b in f.read():
        loader += '0x%02x,' % b
    loader = loader.rstrip(',')

with open(elf_file,"rb") as f:
    elf_data = f.read()


'''
argc

argv
0

envp
0

aux_table.

'''
sc = '''
/*set args and argv*/
    mov x4,0
    mov x0,0
    adr x1,argv_list  /*手动计算..*/
   
    add x2, sp, 0x8
    
__setup_argv:
    ldrb w0,[x1,0]
    cmp w0,0
    beq __setup_argv_ok

    str x1,[x2 , 0x0]
    
    add x2,x2,0x8
    add x4,x4,1
    
    /* go to next string. */   

_goto_next_argv:
    ldrb w0,[x1,0]
    cmp w0,0
    beq _goto_next_argv_ok
    add x1,x1,0x1
    b _goto_next_argv
    
_goto_next_argv_ok:
    add x1,x1,1  
    
    b __setup_argv

__setup_argv_ok:
    adr x0,elf                      /* x0 = file */
    
    mov x1,x4                       /* x1 = argc */
    str x1,[sp,0]                   
    
    add x2, sp , 0x8                /* x2 = argv */
    
    mov x3,0                        /* x3 = envp */
    
    mov x4,sp                       /* x4 = stack*/
    mov x5,0x1                      /* x5 = load_from_mem */
    
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