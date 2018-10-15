#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#include "userprog/process.h"

void syscall_init (void);
int sys_write(int fd, const void *buffer, unsigned size);
void sys_exit (int);

#endif /* userprog/syscall.h */
