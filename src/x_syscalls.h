#ifndef X_SYSCALLS_H
#define X_SYSCALLS_H

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include <fcntl.h>
#include <unistd.h>

void* x_brk(void* addr);
int	x_exit(int status);
int	x_openat(int dirfd,const char *pathname, int flags);
int	x_close(int fd);
int	x_lseek(int fd, off_t offset, int whence);
ssize_t	x_read(int fd, void *buf, size_t count);
ssize_t	x_write(int fd, const void *buf, size_t count);
void	*x_mmap(void *addr, size_t length, int prot,
		int flags, int fd, off_t offset);
int	x_munmap(void *addr, size_t length);
int	x_mprotect(void *addr, size_t length, int prot);
int	*x_perrno(void);

#endif /* Z_SYSCALLS_H */
