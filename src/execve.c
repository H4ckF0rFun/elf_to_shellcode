#include "x_asm.h"
#include "x_syscalls.h"
#include <elf.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#if ELFCLASS == ELFCLASS64
#  define Elf_Ehdr	Elf64_Ehdr
#  define Elf_Phdr	Elf64_Phdr
#  define Elf_auxv_t	Elf64_auxv_t
#elif ELFCLASS == ELFCLASS32
#  define Elf_Ehdr	Elf32_Ehdr
#  define Elf_Phdr	Elf32_Phdr
#  define Elf_auxv_t	Elf32_auxv_t
#endif




#define PAGE_SIZE	4096
#define ALIGN		(PAGE_SIZE - 1)
#define ROUND_PG(x)	(((x) + (ALIGN)) & ~(ALIGN))
#define TRUNC_PG(x)	((x) & ~(ALIGN))
#define PFLAGS(x)	((((x) & PF_R) ? PROT_READ : 0) | \
			 (((x) & PF_W) ? PROT_WRITE : 0) | \
			 (((x) & PF_X) ? PROT_EXEC : 0))

#define LOAD_ERR	((unsigned long)-1)

#define x_alloca __builtin_alloca

#define X_PROG		0
#define X_INTERP	1

__always_inline int x_strlen(const char * s){
	const char * p = s;
	while(*p) ++p;
	return p - s;
}

__always_inline void x_memset(void *s, int c, size_t n)
{
	unsigned char *p = s, *e = p + n;
	while (p < e) *p++ = c;
}


__always_inline void x_memcpy(void *dest, const void *src, size_t n)
{
	unsigned char *d = dest;
	const unsigned char *p = src, *e = p + n;
	while (p < e) *d++ = *p++;
}


__always_inline int check_ehdr(Elf_Ehdr *ehdr)
{
	unsigned char *e_ident = ehdr->e_ident;
	return (e_ident[EI_MAG0] != ELFMAG0 || e_ident[EI_MAG1] != ELFMAG1 ||
		e_ident[EI_MAG2] != ELFMAG2 || e_ident[EI_MAG3] != ELFMAG3 ||
	    	e_ident[EI_CLASS] != ELFCLASS ||
		e_ident[EI_VERSION] != EV_CURRENT ||
		(ehdr->e_type != ET_EXEC && ehdr->e_type != ET_DYN)) ? 0 : 1;
}


__always_inline unsigned long loadelf_anon(int fd, Elf_Ehdr *ehdr, Elf_Phdr *phdr)
{
	unsigned long minva, maxva;
	Elf_Phdr *iter;
	ssize_t sz;
	int flags, dyn = ehdr->e_type == ET_DYN;
	unsigned char *p, *base, *hint;
	unsigned char * brk = NULL;

	minva = (unsigned long)-1;
	maxva = 0;
	
	for (iter = phdr; iter < &phdr[ehdr->e_phnum]; iter++) {
		if (iter->p_type != PT_LOAD)
			continue;
		if (iter->p_vaddr < minva)
			minva = iter->p_vaddr;
		if (iter->p_vaddr + iter->p_memsz > maxva)
			maxva = iter->p_vaddr + iter->p_memsz;
	}

	minva = TRUNC_PG(minva);
	maxva = ROUND_PG(maxva);

	/* For dynamic ELF let the kernel chose the address. */	
	hint = dyn ? NULL : (void *)minva;
	flags = dyn ? 0 : MAP_FIXED;
	flags |= (MAP_PRIVATE | MAP_ANONYMOUS);
	//brk必须往后推.不能落到代码段的位置....
	brk = (unsigned char*) x_brk(NULL);
	if(hint && brk > hint && (brk < (hint + maxva - minva))){
		unsigned char * new_brk = hint + maxva - minva + 0x1000;
		if(new_brk != x_brk(new_brk)){
			return LOAD_ERR;
		}
	}
	/* Check that we can hold the whole image. */
	base = x_mmap(hint, maxva - minva, PROT_NONE, flags, -1, 0);
	if (base == (void *)-1)
		return LOAD_ERR;

	if(x_munmap(base, maxva - minva)){
		return LOAD_ERR;
	}

	flags = MAP_FIXED | MAP_ANONYMOUS | MAP_PRIVATE;
	/* Now map each segment separately in precalculated address. */
	for (iter = phdr; iter < &phdr[ehdr->e_phnum]; iter++) {
		unsigned long off, start;
		if (iter->p_type != PT_LOAD)
			continue;

		off = iter->p_vaddr & ALIGN;
		start = dyn ? (unsigned long)base : 0;
		start += TRUNC_PG(iter->p_vaddr);
		sz = ROUND_PG(iter->p_memsz + off);

		p = x_mmap((void *)start, sz, PROT_WRITE|PROT_READ, flags, -1, 0);
		if (p == (void *)-1)
			goto err;
			
		if (x_lseek(fd, iter->p_offset, SEEK_SET) < 0)
			goto err;
		
		if (x_read(fd, p + off, iter->p_filesz) != 
		(ssize_t)iter->p_filesz)
			goto err;

		x_mprotect(p, sz, PFLAGS(iter->p_flags));
	}

	return (unsigned long)base;
err:
	x_munmap(base, maxva - minva);
	return LOAD_ERR;
}

__always_inline unsigned long loadelf_anon_mem(const char * elf_data, Elf_Ehdr *ehdr, Elf_Phdr *phdr)
{
	unsigned long minva, maxva;
	Elf_Phdr *iter;
	ssize_t sz;
	int flags, dyn = ehdr->e_type == ET_DYN;
	unsigned char *p, *base, *hint;
	unsigned char * brk = NULL;

	minva = (unsigned long)-1;
	maxva = 0;
	
	for (iter = phdr; iter < &phdr[ehdr->e_phnum]; iter++) {
		if (iter->p_type != PT_LOAD)
			continue;
		if (iter->p_vaddr < minva)
			minva = iter->p_vaddr;
		if (iter->p_vaddr + iter->p_memsz > maxva)
			maxva = iter->p_vaddr + iter->p_memsz;
	}

	minva = TRUNC_PG(minva);
	maxva = ROUND_PG(maxva);

	/* For dynamic ELF let the kernel chose the address. */	
	hint = dyn ? NULL : (void *)minva;
	flags = dyn ? 0 : MAP_FIXED;
	flags |= (MAP_PRIVATE | MAP_ANONYMOUS);

	brk = (unsigned char*) x_brk(NULL);
	if(hint && brk > hint && (brk < (hint + maxva - minva))){
		unsigned char * new_brk = hint + maxva - minva + 0x1000;
		if(new_brk != x_brk(new_brk)){
			return LOAD_ERR;
		}
	}

	/* Check that we can hold the whole image. */
	base = x_mmap(hint, maxva - minva, PROT_NONE, flags, -1, 0);
	if (base == (void *)-1)
		return -1;

	if(x_munmap(base, maxva - minva)){
		return -1;
	}

	flags = MAP_FIXED | MAP_ANONYMOUS | MAP_PRIVATE;
	/* Now map each segment separately in precalculated address. */
	for (iter = phdr; iter < &phdr[ehdr->e_phnum]; iter++) {
		unsigned long off, start;
		if (iter->p_type != PT_LOAD)
			continue;

		off = iter->p_vaddr & ALIGN;
		start = dyn ? (unsigned long)base : 0;
		start += TRUNC_PG(iter->p_vaddr);
		sz = ROUND_PG(iter->p_memsz + off);

		p = x_mmap((void *)start, sz, PROT_WRITE|PROT_READ, flags, -1, 0);
		if (p == (void *)-1)
			goto err;

		x_memcpy(p + off,elf_data + iter->p_offset,iter->p_filesz);
		
		x_mprotect(p, sz, PFLAGS(iter->p_flags));
	}

	return (unsigned long)base;
err:
	x_munmap(base, maxva - minva);
	return LOAD_ERR;
}


/*
		如果程序中有使用 /proc/self/exe 就会导致失败.....
*/

__always_inline char * copy_strings(int argc,const char * argv[],const char * envp[]){
	int    len  = 0;
	char * buff = 0;
	char * p    = 0;
	for(int i = 0;i<argc;i++){
		len += x_strlen(argv[i]) + 1;
	}

	for(int i = 0;envp[i];i++){
		len += x_strlen(envp[i]) + 1;
	}
	
	len += 1;
	len = (len + 0xfff) & (~0xfff);

	buff = x_mmap(0x0,len,PROT_READ|PROT_WRITE,MAP_PRIVATE | MAP_ANON,-1,0);
	if (MAP_FAILED == (void*)buff){
		return 0;
	}

	//copy argv.
	p = buff;
	for(int i = 0;i < argc; i++){
		int copy = x_strlen(argv[i]) + 1;
		x_memcpy(p,argv[i],copy);
		p += copy;
	}

	//copy envp.
	for(int i = 0;envp[i];i++){
		int copy = x_strlen(envp[i]) + 1;
		x_memcpy(p,envp[i],copy);
		p += copy;
	}
	*p = '\x00';

	return buff;
}

__attribute__((optimize("no-tree-loop-distribute-patterns")))
void x_execve(const char * file,int argc, const char ** argv,const char ** envp,long* sp,int load_from_mem)		//no_return
{
	Elf_Ehdr ehdrs[2], *ehdr = ehdrs;
	Elf_Phdr *phdr, *iter;
	unsigned long base[2], entry[2];
	Elf_auxv_t *av;
	char * elf_interp = NULL;
	int    i = 0;
	int    sz = 0;
	const char ** p, *s ;
	int fd = 0;
	const char*  null = NULL, * strings = NULL;

	if(envp == NULL){
		envp = &null;
	}
	
	strings = copy_strings(argc,argv,envp);

	if(!strings){
		x_exit(-1);
	}

	/* map */
	for (i = 0;; i++, ehdr++) {
		if(elf_interp || !load_from_mem){
			fd = x_openat(AT_FDCWD,file,O_RDONLY);
			
			if(fd < 0)
				x_exit(-2);
			
			if (x_read(fd, ehdr, sizeof(*ehdr)) != sizeof(*ehdr))
				x_exit(-3);
			
		}else{
			x_memcpy(ehdr,file,sizeof(*ehdr));
		}

		if (!check_ehdr(ehdr)){
			x_exit(-4);
		}

		/* Read the program header. */
		sz = ehdr->e_phnum * sizeof(Elf_Phdr);
		phdr = x_alloca(sz);

		if(elf_interp || !load_from_mem){
			if (x_lseek(fd, ehdr->e_phoff, SEEK_SET) < 0){
				x_exit(-5);
			}
			if (x_read(fd, phdr, sz) != sz){
				x_exit(-6);
			}
		}else{
			x_memcpy(phdr,file + ehdr->e_phoff,sz);
		}
		
		if(elf_interp || !load_from_mem){
			base[i] = loadelf_anon(fd, ehdr, phdr);
		}else{
			base[i] = loadelf_anon_mem(file, ehdr, phdr);
		}

		if (base[i] == LOAD_ERR){
			x_exit(-7);
		}
		
		/* Set the entry point, if the file is dynamic than add bias. */
		entry[i] = ehdr->e_entry + (ehdr->e_type == ET_DYN ? base[i] : 0);
		
		/* The second round, we've loaded ELF interp. */
		if (file == elf_interp){
			x_close(fd);
			break;
		}

		//find interpreter in elf
		for (iter = phdr; iter < &phdr[ehdr->e_phnum]; iter++) {
			if (iter->p_type != PT_INTERP)
				continue;

			elf_interp = x_alloca(iter->p_filesz);

			if(!load_from_mem){
				if (x_lseek(fd, iter->p_offset, SEEK_SET) < 0){
					x_exit(-8);
				}
				if (x_read(fd, elf_interp, iter->p_filesz) !=
						(ssize_t)iter->p_filesz){
					x_exit(-9);
				}
			}else{
				x_memcpy(elf_interp,file + iter->p_offset,iter->p_filesz);
			}
			
			if (elf_interp[iter->p_filesz - 1] != '\0'){
				x_exit(-10);
			}
		}
		/* Looks like the ELF is static -- leave the loop. */
		if (elf_interp == NULL)
			break;

		file = elf_interp;

		if(!load_from_mem){
			x_close(fd);
		}
	}

	//align
	sp = (long*)((0xf + (long)sp) & ( ~0xfl));

	/* copy argv and envp */
	*sp = argc;
	p = 1 + (const char**)sp;

	s = strings;
	for (i = 0;i < argc;i++,p++){
		*p = s;
		s += x_strlen(s) + 1;		//goto next string...
	}

	*p++ = 0x0;

	while(*s){
		*p = s;
		s += x_strlen(s) + 1;
		++p;
	}

	*p++ = 0;

	/* create elf table */
	av = (Elf_auxv_t*)p;
	
	/* copied from linux kernel .... */
#define NEW_AUX_ENT(id, val) \
do { \
	av->a_type = id; \
	av->a_un.a_val = val; \
	av++; \
} while (0); \

	NEW_AUX_ENT(AT_HWCAP, 0);
	NEW_AUX_ENT(AT_PAGESZ, 0x1000);
	NEW_AUX_ENT(AT_CLKTCK, 1000000L);
	NEW_AUX_ENT(AT_PHDR, base[X_PROG] + ehdrs[X_PROG].e_phoff);
	NEW_AUX_ENT(AT_PHENT, ehdrs[X_PROG].e_phentsize);
	NEW_AUX_ENT(AT_PHNUM, ehdrs[X_PROG].e_phnum);
	NEW_AUX_ENT(AT_BASE, elf_interp ? base[X_INTERP] : 0);		//base address of interpreter 
	NEW_AUX_ENT(AT_ENTRY, entry[X_PROG]);						//entry of program.
	NEW_AUX_ENT(AT_EXECFN, (unsigned long)argv[0]);
	NEW_AUX_ENT(AT_RANDOM,(unsigned long)(av + 6));								//这里得是一段可读可写的区域.go的程序会修改random bytes.
	NEW_AUX_ENT(AT_UID, 0);
	NEW_AUX_ENT(AT_EUID, 0);
	NEW_AUX_ENT(AT_GID, 0);
	NEW_AUX_ENT(AT_EGID, 0);
	NEW_AUX_ENT(AT_NULL,0);										//end flag....
	
#undef NEW_AUX_ENT
	//run
	x_trampo((void (*)(void))(elf_interp ? entry[X_INTERP] : entry[X_PROG]), sp);
	x_exit(0);
}


// #include <stdio.h>
// #include <stdlib.h>

// int main(int argc,const char ** argv,const char ** envp){
    
//     if(argc < 2){
//         exit(1);
//     }
//     long stack[0x100];

//     FILE * fp = fopen(argv[1],"rb");
// 	fseek(fp,0,SEEK_END);
// 	int len = ftell(fp);
// 	fseek(fp,0,SEEK_SET);
	
// 	printf("elf size : %d\n",len);
// 	char * elf = (char*)malloc(len);
// 	fread(elf,1,len,fp);

//     x_execve(elf,argc-1,argv+1,envp,&stack,1);
//     return 0;
// }
