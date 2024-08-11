#ifndef X_ASM_H
#define X_ASM_H

#define PUBLIC __attribute__((visibility ("default")))
#define PRIVATE __attribute__((visibility ("hidden")))

PRIVATE void x_trampo(void (*entry)(void), long *sp);
PRIVATE long x_syscall(int n, ...);

#endif 

