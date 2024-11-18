#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>
#include <sys/syscall.h>   /* For SYS_xxx definitions */

void *mmap(void *addr, size_t length, int prot, int flags,
                  int fd, off_t offset);
int munmap(void *addr, size_t length);


long syscall(long number, ...);

int main(int argc,char * argv[]){
        if (argc != 2){
		printf("Usage : %s <shellcode>\n",argv[0]);
		exit(1);
	}
        FILE * fp = fopen(argv[1],"rb");
        if(!fp){
                return -1;
        }

        fseek(fp,0,SEEK_END);
        int len = ftell(fp);

        void * shellcode = mmap(0,len,PROT_READ|PROT_EXEC|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);

        if(shellcode == MAP_FAILED){
                perror("mmap failed");
                return -1;
        }

        fseek(fp,0,SEEK_SET);
        fread(shellcode,1,len,fp);
        
        __clear_cache(shellcode,len + (char*)shellcode);
        ((void (*)()) shellcode)();
        return 0;
}
