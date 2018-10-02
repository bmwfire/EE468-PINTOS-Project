#include "devices/shutdown.h"
#include "devices/input.h"
#include "userprog/syscall.h"
#include "userprog/process.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "filesys/inode.h"
#include "filesys/directory.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "lib/kernel/list.h"

// declearing for user 
static void syscall_handler (struct intr_frame *);
static void check_user (const uint8_t *uaddr);
static int32_t get_user (const uint8_t *uaddr);
static bool put_user (uint8_t *udst, uint8_t byte);
static int memread_user (void *src, void *des, size_t bytes);

enum fd_search_filter { FD_FILE = 1, FD_DIRECTORY = 2 };
static struct file_desc* find_file_desc(struct thread *, int fd, enum fd_search_filter flag);

// declear system calling 
void sys_halt (void);
void sys_exit (int);
bool sys_create(const char* filename, unsigned initial_size);
bool sys_remove(const char* filename);

void 
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

// in case of invalid memory access, fail and exit.
static void fail_invalid_access(void) {
  if (lock_held_by_current_thread(&filesys_lock))
    lock_release (&filesys_lock);
    sys_exit (-1);
    NOT_REACHED();
}

static void
syscall_handler (struct intr_frame *f)
{
  int syscall_number;
  ASSERT( sizeof(syscall_number) == 4 ); // assuming x86

  // The system call number is in the 32-bit word at the caller's stack pointer.
  memread_user(f->esp, &syscall_number, sizeof(syscall_number));
  //_DEBUG_PRINTF ("[DEBUG] system call, number = %d!\n", syscall_number);

  // Store the esp, which is needed in the page fault handler.
  // refer to exception.c:page_fault() (see manual 4.3.3)
  thread_current()->current_esp = f->esp;

  // Dispatch w.r.t system call number
  // SYS_*** constants are defined in syscall-nr.h
  switch (syscall_number) {
  case SYS_HALT: // 0
    {
      sys_halt();
      NOT_REACHED();
      break;
    }

  case SYS_EXIT: // 1
    {
      int exitcode;
      memread_user(f->esp + 4, &exitcode, sizeof(exitcode));
      sys_exit(exitcode);
      NOT_REACHED();
      break;
    }
      
case SYS_CREATE: // 2
    {
      const char* filename;
      unsigned initial_size;
      bool return_code;

      memread_user(f->esp + 4, &filename, sizeof(filename));
      memread_user(f->esp + 8, &initial_size, sizeof(initial_size));

      return_code = sys_create(filename, initial_size);
      f->eax = return_code;
      break;
    }

  case SYS_REMOVE: // 3
    {
      const char* filename;
      bool return_code;

      memread_user(f->esp + 4, &filename, sizeof(filename));

      return_code = sys_remove(filename);
      f->eax = return_code;
      break;
    }      
  /* unhandled case */
  default:
    printf("[ERROR] system call %d is unimplemented!\n", syscall_number);

    // ensure that waiting (parent) process should wake up and terminate.
    sys_exit(-1);
    break;
  }
}

//*********************             System Call Implementations 

void sys_halt(void) {
  shutdown_power_off();
}

void sys_exit(int status) {
  printf("%s: exit(%d)\n", thread_current()->name, status);
  
  // The process exits.
  // wake up the parent process (if it was sleeping) using semaphore,
  // and pass the return code.
  struct process_control_block *pcb = thread_current()->pcb;
  if(pcb != NULL) {
    pcb->exitcode = status;
  }
  else {
    // pcb == NULL probably means that previously
    // page allocation has failed in process_execute()
  }
  thread_exit();
}

bool sys_create(const char* filename, unsigned initial_size) {
  bool return_code;

  // memory validation
  check_user((const uint8_t*) filename);
  lock_acquire (&filesys_lock);
  return_code = filesys_create(filename, initial_size, false);
  lock_release (&filesys_lock);
  return return_code;
}

bool sys_remove(const char* filename) {
  bool return_code;
  // memory validation
  check_user((const uint8_t*) filename);

  lock_acquire (&filesys_lock);
  return_code = filesys_remove(filename);
  lock_release (&filesys_lock);
  return return_code;
}

//******              Helper Functions on Memory Access 

static void
check_user (const uint8_t *uaddr) {
  // check uaddr range or segfaults
  if(get_user (uaddr) == -1)
    fail_invalid_access();
}

/*
 * Reads a single 'byte' at user memory admemory at 'uaddr'.
 * 'uaddr' must be below PHYS_BASE.
 * Returns the byte value if successful (extract the least significant byte),
 * or -1 in case of error (a segfault occurred or invalid uaddr)
 */
static int32_t
get_user (const uint8_t *uaddr) {
  // check that a user pointer `uaddr` points below PHYS_BASE
  if (! ((void*)uaddr < PHYS_BASE)) {
    return -1;
  }

  // as suggested in the (3.1.5) reference manual
  int result;
  asm ("movl $1f, %0; movzbl %1, %0; 1:"
      : "=&a" (result) : "m" (*uaddr));
  return result;
}

/* Writes a single byte (content is 'byte') to user address 'udst'.
 * 'udst' must be below PHYS_BASE.
 * Returns true if successful, false if a segfault occurred.
 */
 
static bool
put_user (uint8_t *udst, uint8_t byte) {
  // check that a user pointer `udst` points below PHYS_BASE
  if (! ((void*)udst < PHYS_BASE)) {
    return false;
  }

  int error_code;

 // as suggested in the (3.1.5) reference manual
  asm ("movl $1f, %0; movb %b2, %1; 1:"
      : "=&a" (error_code), "=m" (*udst) : "q" (byte));
  return error_code != -1;
}


/**
 * Reads a consecutive `bytes` bytes of user memory with the
 * starting address `src` (uaddr), and writes to dst.
 * Returns the number of bytes read.
 * In case of invalid memory access, exit() is called and consequently
 * the process is terminated with return code -1.
 */
static int
memread_user (void *src, void *dst, size_t bytes)
{
  int32_t value;
  size_t i;
  for(i=0; i<bytes; i++) {
    value = get_user(src + i);
    if(value == -1) // segfault or invalid memory access
      fail_invalid_access();

    *(char*)(dst + i) = value & 0xff;
  }
  return (int)bytes;
}
