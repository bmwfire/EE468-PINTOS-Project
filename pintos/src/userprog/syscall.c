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
#include "userprog/process.h"
#include "threads/malloc.h"
#include <string.h>
#include "threads/synch.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "devices/shutdown.h"

static void syscall_handler (struct intr_frame *);
void sys_exit (int);
void sys_halt(void);
int sys_exec (const char *cmdline);

struct lock filesys_lock;

bool is_valid_ptr(const void *user_ptr);
//void sys_halt();

enum fd_search_filter { FD_FILE = 1, FD_DIRECTORY = 2 };
// static struct file_desc* find_file_desc(struct thread *, int fd, enum fd_search_filter flag);
struct file_descriptor * retrieve_file(int fd);

struct file_descriptor{
  int fd_num;
  tid_t owner;
  struct file *file_struct;
  struct list_elem elem;
};

// struct list open_files;
struct lock filesys_lock;

void
syscall_init (void)
{
  lock_init(&filesys_lock);
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
  printf("SYSCALL: Entered syscall\n");

  // The system call number is in the 32-bit word at the caller's stack pointer.

  esp = f->esp;
  printf("SYSCALL: esp is %d\n", *esp);
  if(!is_valid_ptr(esp)){
    printf("SYSCALL: esp invalid pointer\n");
    sys_exit(-1);
  }
  // Dispatch w.r.t system call number
  // SYS_*** constants are defined in syscall-nr.h
  switch (*esp) {
  case SYS_HALT: // 0
    {
      sys_halt();
      break;
    }
  case SYS_EXIT: // 1
    {
      is_valid_ptr(f->esp+1);
      break;
    }
  case SYS_REMOVE:
    {
      // TODO
      // const char* filename;
      // bool ret;
      //
      // lock_acquire (&filesys_lock);
      // ret = filesys_remove(filename);
      // lock_release (&filesys_lock);
      //
      // f->eax = ret;
      break;
    }
  case SYS_WRITE:
    {
      printf("WRITE: starting syswrite with esp = %d\n", *esp);
      if(is_valid_ptr((const void*)(esp+1)) && is_valid_ptr( (const void*) (esp+2)) && is_valid_ptr((const void*)(esp+3)))
      {
        printf("WRITE: size = %d\n", *(esp+3));
        if(is_valid_ptr((const void*)(*(esp+2))) && is_valid_ptr((const void*)((*(esp+2)+*(esp+3)-1))))
          f->eax = (uint32_t) sys_write((int) *(esp+1), (const void*) *(esp+2), (unsigned) *(esp+3));
        else{
          if(!is_valid_ptr((const void*)(*(esp+2)))){
            printf("Write: %s \n", (char *)(esp + 2));
            printf("write: %x \n", (esp + 2));
            printf("write: %x \n", *(esp + 2));
            printf("WRITE: *(esp+2) invalid \n");
          }
          if(!is_valid_ptr((const void*)((*(esp+2)+*(esp+3)-1)))){
            printf("WRITE: (*(esp+2)+*(esp+3)-1) invalid \n");
          }
          printf("WRITE: Pointer found as invalid 2\n");
          sys_exit(-1);
        }
      }else{
        printf("WRITE: Pointer found as invalid 1\n");
        sys_exit(-1);
      }
      break;
    }
  case SYS_EXEC:
    {
      // Validate the pointer to the first argument on the stack
      if(!is_valid_ptr((void*)(esp + 1)))
        sys_exit(-1);

      // Validate the buffer that the first argument is pointing to, this is a pointer to the command line args
      // that include the filename and additional arguments for process execute
      if(!is_valid_ptr((void *)*(esp + 1)))
        sys_exit(-1);

      // pointers are valid, call sys_exec and save result to eax for the interrupt frame
      f->eax = sys_exec((const char *)*(esp + 1));
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

int sys_exec (const char *cmdline){
  char * cmdline_cp;
  char * ptr;
  char * file_name;
  struct file * f;
  int return_value;
  // copy command line to parse and obtain filename to open
  cmdline_cp = malloc(strlen(cmdline)+1);
  strlcpy(cmdline_cp, cmdline, strlen(cmdline)+1);
  file_name = strtok_r(cmdline_cp, " ", &ptr);


  // it is not safe to call into the file system code provided in "filesys" directory from multiple threads at once
  // your system call implementation must treat the file system code as a critical section
  // Don't forget the process_execute() also accesses files.
  // => Obtain lock for file system
  lock_acquire(&filesys_lock);

  // try and open file name
  f = filesys_open(file_name);

  // f will be null if file not found in file system
  if (f==NULL){
    // nothing to do here exec fails, release lock and return -1
    lock_release(&filesys_lock);
    return -1;
  } else {
    // file exists, we can close file and call our implemented process_execute() to run the executable
    // note that process_execute accesses filesystem so hold onto lock until it is complete
    file_close(f);
    return_value = process_execute(cmdline);
    lock_release(&filesys_lock);
    return return_value;
  }
}

void sys_halt(void) {
  shutdown_power_off();
}

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
  if(user_ptr != NULL && is_user_vaddr(user_ptr))
  {
    return (pagedir_get_page(curr->pagedir, user_ptr)) != NULL;
  }
  if(user_ptr == NULL){
    printf("Pointer is NULL\n");
  }else{
    printf("Pointer is not user address space\n");
  }
  return false;
}

int sys_write(int fd, const void *buffer, unsigned size) {
  printf("WRITE: fd = %d, size = %d\n", fd, size);
  struct file_descriptor *fd_struct;
  int bytes_written = 0;

  lock_acquire(&filesys_lock);

  if(fd == STDIN_FILENO){
    lock_release(&filesys_lock);
    return -1;
  }
  if(fd == STDOUT_FILENO){
    putbuf (buffer, size);
    lock_release(&filesys_lock);
    return size;
  }

  fd_struct = retrieve_file(fd);
  if(fd_struct != NULL){
    bytes_written = file_write(fd_struct->file_struct, buffer, size);
  }

  lock_release(&filesys_lock);
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
