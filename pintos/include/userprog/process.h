#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"

tid_t process_create_initd(const char *file_name);
tid_t process_fork(const char *name, struct intr_frame *if_);
int process_exec(void *f_name);
int process_wait(tid_t);
void process_exit(void);
void process_activate(struct thread *next);
// process_exec()에서 사용할 함수 선언
// static void argument_stack(char **argv, int argc, struct intr_frame *if_);
static void argument_stack(char **argv, int argc, struct intr_frame *if_, void *buffer);
/* 7.28 추가 자식 pid 구하기 */
struct thread *get_child_with_pid(tid_t tid);
#endif /* userprog/process.h */
