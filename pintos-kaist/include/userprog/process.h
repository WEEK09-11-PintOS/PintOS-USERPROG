#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include "filesys/file.h"

tid_t process_create_initd (const char *file_name);
tid_t process_fork (const char *name, struct intr_frame *if_);
int process_exec (void *f_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (struct thread *next);

tid_t process_execute(const char *file_name); // 실행 요청
struct thread *get_child_by_tid(tid_t child_tid);

// File System 관련 함수
int process_add_file(struct file *file);
struct file *process_get_file(int fd);
void process_close_file(int fd);
void process_close_all_files(void);

#endif /* userprog/process.h */
