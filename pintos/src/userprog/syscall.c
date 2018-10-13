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
#include "lib/user/syscall.h"
#include "userprog/pagedir.h"
// #include <unistd.h>
// #include <sys/types.h>

static void syscall_handler (struct intr_frame *);
void sys_exit (int);


static void check_user (const uint8_t *uaddr);
static int32_t get_user (const uint8_t *uaddr);
bool is_valid_ptr(const void *user_ptr);
//void sys_halt();

static int memread_user (void *src, void *dst, size_t bytes);
enum fd_search_filter { FD_FILE = 1, FD_DIRECTORY = 2 };
// static struct file_desc* find_file_desc(struct thread *, int fd, enum fd_search_filter flag);
struct file_descriptor * retrieve_file(int fd);

struct file_descriptor{
  int fd_num;
  tid_t owner;
  struct file *file_struct;
  struct list_elem elem;
};

struct lock fs_lock;
// struct list open_files;
struct lock filesys_lock;

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
  uint32_t *esp;

  //int syscall_number;
  //ASSERT( sizeof(syscall_number) == 4 ); // assuming x86

  // The system call number is in the 32-bit word at the caller's stack pointer.
  //memread_user(f->esp, &syscall_number, sizeof(syscall_number));

  // Store the esp, which is needed in the page fault handler.
  // refer to exception.c:page_fault() (see manual 4.3.3)
  //thread_current()->current_esp = f->esp;
  esp = f->esp;
  if(is_valid_ptr(esp)){
    sys_exit(-1);
  }
  // Dispatch w.r.t system call number
  // SYS_*** constants are defined in syscall-nr.h
  switch (*esp) {
  case SYS_HALT: // 0
    {
      // sys_halt();
      NOT_REACHED();
      break;
    }

  case SYS_EXIT: // 1
    {
      //int exitcode;
      //memread_user(f->esp + 4, &exitcode, sizeof(exitcode));
      is_valid_ptr(f->esp+1);
      //sys_exit(f->esp+1);
      //NOT_REACHED();
      break;
    }

  case SYS_WAIT:
    {
      pid_t pid;
      //int pid;
      memread_user(f->esp + 4, &pid, sizeof(int));//if pid_t gets working, change int to pid_t
      int ret = process_wait(pid);
      f->eax = (uint32_t) ret;
      break;
    }

  case SYS_TELL:
    {
      // int fd;
      // unsigned ret;
      //
      // memread_user(f->esp + 4, &fd, sizeof(fd));
      //
      // lock_acquire (&filesys_lock);
      // struct file_desc* file_d = find_file_desc(thread_current(), fd, FD_FILE);
      //
      // if(file_d && file_d->file) {
      //   ret = file_tell(file_d->file);
      // }
      // else
      //   ret = -1;
      //
      // lock_release (&filesys_lock);
      // f->eax = (uint32_t) ret;
      break;
    }
  case SYS_REMOVE:
    {
      const char* filename;
      bool ret;

      memread_user(f->esp + 4, &filename, sizeof(filename));
      check_user((const uint8_t*) filename);
      lock_acquire (&filesys_lock);
      ret = filesys_remove(filename);
      lock_release (&filesys_lock);

      f->eax = ret;
      break;
    }
  case SYS_WRITE:
    {
      printf("WRITE: starting syswrite with esp = %d\n", *esp);
      if(is_valid_ptr((const void*)(esp+1)) && is_valid_ptr( (const void*) (esp+2)) && is_valid_ptr((const void*)(esp+3)))
      {
        if(is_valid_ptr((const void*)(*(esp+2))) && is_valid_ptr((const void*)(*(esp+2+(*esp+3)-1))))
          f->eax = (uint32_t) sys_write((int) *(esp+1), (const void*) *(esp+2), (unsigned) *(esp+3));
        else{
          printf("WRITE: Pointer found as invalid 1\n");
          sys_exit(-1);
        }
      }else{
        printf("WRITE: Pointer found as invalid 2\n");
        sys_exit(-1);
      }
      break;
    }

  /* unhandled case */
  default:
    printf("[ERROR] a system call is unimplemented!\n");

    // ensure that waiting (parent) process should wake up and terminate.
    sys_exit(-1);
    break;
  }
}

// void sys_halt() {
//   shutdown_power_off();
// }

void sys_exit(int status) {
  printf("%s: exit(%d)\n", thread_current()->name, status);

  // The process exits.
  // wake up the parent process (if it was sleeping) using semaphore,
  // and pass the return code.
  // struct process_control_block *pcb = thread_current()->pcb;
  // if(pcb != NULL) {
  //   pcb->exitcode = status;
  // }
  // else {
  //   // pcb == NULL probably means that previously
  //   // page allocation has failed in process_execute()
  // }
  thread_exit();
}


/* The kernel must be very careful about doing so, because the user can pass
 * a null pointer, a pointer to unmapped virtual memory, or a pointer to
 * kernel virtual address space (above PHYS_BASE). All of these types of
 * invalid pointers must be rejected without harm to the kernel or other
 * running processes, by terminating the offending process and freeing its
 * resources */
bool is_valid_ptr(const void *user_ptr)
{
  struct thread *curr = thread_current();
  if(user_ptr != NULL && is_user_vaddr (user_ptr))
  {
    return (pagedir_get_page(curr->pagedir, user_ptr)) != NULL;
  }
  return false;
}

int sys_write(int fd, const void *buffer, unsigned size) {
  printf("WRITE: fd = %d, size = %d\n", fd, size);
  struct file_descriptor *fd_struct;
  int bytes_written = 0;

  lock_acquire(&fs_lock);

  if(fd == STDIN_FILENO){
    lock_release(&fs_lock);
    return -1;
  }
  if(fd == STDOUT_FILENO){
    putbuf (buffer, size);
    lock_release(&fs_lock);
    return size;
  }

  fd_struct = retrieve_file(fd);
  if(fd_struct != NULL){
    bytes_written = file_write(fd_struct->file_struct, buffer, size);
  }

  lock_release(&fs_lock);
  return bytes_written;
}

struct file_descriptor * retrieve_file(int fd){
  struct list_elem *list_element;
  struct file_descriptor *fd_struct;
  for(list_element = list_head(&thread_current()->open_files); list_element != list_tail(&thread_current()->open_files);
  list_element = list_next(list_element)){
    fd_struct = list_entry (list_element, struct file_descriptor, elem);
    if (fd_struct->fd_num == fd)
      return fd_struct;
  }
  //This is done for the tail
  fd_struct = list_entry (list_element, struct file_descriptor, elem);
  if (fd_struct->fd_num == fd)
    return fd_struct;

  return NULL;
}



static void
check_user (const uint8_t *uaddr) {

  if(get_user (uaddr) == -1)
    fail_invalid_access();
}

// static struct file_desc*
// find_file_desc(struct thread *t, int fd, enum fd_search_filter flag)
// {
//   ASSERT (t != NULL);
//
//   if (fd < 3) {
//     return NULL;
//   }
//
//   struct list_elem *e;
//
//   // if (! list_empty(&t->file_descriptors)) {
//   //   for(e = list_begin(&t->file_descriptors);
//   //       e != list_end(&t->file_descriptors); e = list_next(e))
//   //   {
//   //     struct file_desc *desc = list_entry(e, struct file_desc, elem);
//   //     if(desc->id == fd) {
//   //       // found. filter by flag to distinguish file and directorys
//   //       if (desc->dir != NULL && (flag & FD_DIRECTORY) )
//   //         return desc;
//   //       else if (desc->dir == NULL && (flag & FD_FILE) )
//   //         return desc;
//   //     }
//   //   }
//   // }
//
//   return NULL; // not found
// }

static int32_t
get_user (const uint8_t *uaddr) {
  // check that a user pointer `uaddr` points below PHYS_BASE
  if (! ((void*)uaddr < PHYS_BASE)) {
    return -1;
  }

  // as suggested in the reference manual, see (3.1.5)
  int result;
  asm ("movl $1f, %0; movzbl %1, %0; 1:"
      : "=&a" (result) : "m" (*uaddr));
  return result;
}

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
