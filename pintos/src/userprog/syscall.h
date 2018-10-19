#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#include "userprog/process.h"

void syscall_init (void);
int sys_write(int fd, const void *buffer, unsigned size);
void close_thread_files(tid_t tid)

#endif /* userprog/syscall.h */
