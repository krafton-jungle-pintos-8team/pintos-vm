/* This file is derived from source code for the Nachos
instructional operating system.  The Nachos copyright notice
is reproduced in full below. */

/* Copyright (c) 1992-1996 The Regents of the University of California.
All rights reserved.

Permission to use, copy, modify, and distribute this software
and its documentation for any purpose, without fee, and
without written agreement is hereby granted, provided that the
above copyright notice and the following two paragraphs appear
in all copies of this software.

IN NO EVENT SHALL THE UNIVERSITY OF CALIFORNIA BE LIABLE TO
ANY PARTY FOR DIRECT, INDIRECT, SPECIAL, INCIDENTAL, OR
CONSEQUENTIAL DAMAGES ARISING OUT OF THE USE OF THIS SOFTWARE
AND ITS DOCUMENTATION, EVEN IF THE UNIVERSITY OF CALIFORNIA
HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

THE UNIVERSITY OF CALIFORNIA SPECIFICALLY DISCLAIMS ANY
WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
PURPOSE.  THE SOFTWARE PROVIDED HEREUNDER IS ON AN "AS IS"
BASIS, AND THE UNIVERSITY OF CALIFORNIA HAS NO OBLIGATION TO
PROVIDE MAINTENANCE, SUPPORT, UPDATES, ENHANCEMENTS, OR
MODIFICATIONS.
*/

#include "threads/synch.h"

#include <stdio.h>
#include <string.h>

#include "threads/interrupt.h"
#include "threads/thread.h"

static bool higher_priority_sema(const struct list_elem *a_, const struct list_elem *b_,
                                 void *aux UNUSED);

/* Initializes semaphore SEMA to VALUE. A semaphore is a
nonnegative integer along with two atomic operators for
manipulating it:

- down or "P": wait for the value to become positive, then
decrement it.

- up or "V": increment the value (and wake up one waiting
thread, if any). */
void sema_init(struct semaphore *sema, unsigned value) {
    ASSERT(sema != NULL);

    sema->value = value;
    list_init(&sema->waiters);
}

/* 세마포어의 Wait() 또는 P 연산.
    값이 0이면 , 누군가가 깨워줄 때까지 blocked 상태로 대기
*/
void sema_down(struct semaphore *sema) {
    enum intr_level old_level;

    ASSERT(sema != NULL);

    //인터럽트 처리중에는 절대로 잠들면 안됨 => 데드락 발생가능
    ASSERT(!intr_context());

    old_level = intr_disable();  // 인터럽트 OFF

    while (sema->value == 0) {  // 만약 sema가 "0" 이면
        // list_push_back(&sema->waiters, &thread_current()->elem);
        list_insert_ordered(&sema->waiters, &thread_current()->elem, higher_priority, NULL);
        thread_block();  // wait_list 에 넣기 => 쓰레드 블록상태
    }
    sema->value--;

    intr_set_level(old_level);  // 인터럽트 ON
}

/* Down or "P" operation on a semaphore, but only if the
semaphore is not already 0.  Returns true if the semaphore is
decremented, false otherwise.

This function may be called from an interrupt handler. */
bool sema_try_down(struct semaphore *sema) {
    enum intr_level old_level;
    bool success;

    ASSERT(sema != NULL);

    old_level = intr_disable();
    if (sema->value > 0) {
        sema->value--;
        success = true;
    } else
        success = false;
    intr_set_level(old_level);

    return success;
}

/* 세마포어의 Signal() 또는 V 연산.
    대기 리스트에서 깨어남
*/
void sema_up(struct semaphore *sema) {
    enum intr_level old_level;
    struct thread *t = NULL;
    ASSERT(sema != NULL);

    old_level = intr_disable();  // 인터럽트 OFF

    if (!list_empty(&sema->waiters)) {
        list_sort(&sema->waiters, higher_priority, NULL);  //우선순위대로 정렬
        t = list_entry(list_pop_front(&sema->waiters), struct thread, elem);
        thread_unblock(t);  // 잠들어있는 쓰레드 깨우기 -> Ready_list에 정렬해서 넣기
    }
    sema->value++;

    intr_set_level(old_level);  // 인터럽트 ON

    // CPU 양보
    thread_try_yield();
}

static void sema_test_helper(void *sema_);

/* Self-test for semaphores that makes control "ping-pong"
between a pair of threads.  Insert calls to printf() to see
what's going on. */
void sema_self_test(void) {
    struct semaphore sema[2];
    int i;

    printf("Testing semaphores...");
    sema_init(&sema[0], 0);
    sema_init(&sema[1], 0);
    thread_create("sema-test", PRI_DEFAULT, sema_test_helper, &sema);
    for (i = 0; i < 10; i++) {
        sema_up(&sema[0]);
        sema_down(&sema[1]);
    }
    printf("done.\n");
}

/* Thread function used by sema_self_test(). */
static void sema_test_helper(void *sema_) {
    struct semaphore *sema = sema_;
    int i;

    for (i = 0; i < 10; i++) {
        sema_down(&sema[0]);
        sema_up(&sema[1]);
    }
}

/* Initializes LOCK.  A lock can be held by at most a single
thread at any given time.  Our locks are not "recursive", that
is, it is an error for the thread currently holding a lock to
try to acquire that lock.

A lock is a specialization of a semaphore with an initial
value of 1.  The difference between a lock and such a
semaphore is twofold.  First, a semaphore can have a value
greater than 1, but a lock can only be owned by a single
thread at a time.  Second, a semaphore does not have an owner,
meaning that one thread can "down" the semaphore and then
another one "up" it, but with a lock the same thread must both
acquire and release it.  When these restrictions prove
onerous, it's a good sign that a semaphore should be used,
instead of a lock. */
void lock_init(struct lock *lock) {
    ASSERT(lock != NULL);

    lock->holder = NULL;
    sema_init(&lock->semaphore, 1);
}

/* Acquires LOCK, sleeping until it becomes available if
necessary.  The lock must not already be held by the current
thread.

This function may sleep, so it must not be called within an
interrupt handler.  This function may be called with
interrupts disabled, but interrupts will be turned back on if
we need to sleep. */
void lock_acquire(struct lock *lock) {
    ASSERT(lock != NULL);
    ASSERT(!intr_context());
    ASSERT(!lock_held_by_current_thread(lock));
    struct thread *hold_t = lock->holder;
    struct thread *now_t = thread_current();
    enum intr_level old_level = intr_disable();
    now_t->wait_on_lock = lock;
    if (hold_t != NULL && hold_t->priority < now_t->priority) {
        list_insert_ordered(&hold_t->donation_list, &now_t->donation_elem, lower_priority, NULL);
        hold_t->priority = get_high_donation(hold_t);
        set_donations_priority(hold_t);
    }
    sema_down(&lock->semaphore);

    lock->holder = thread_current();
    lock->holder->wait_on_lock = NULL;
    intr_set_level(old_level);
}

/* Tries to acquires LOCK and returns true if successful or false
on failure.  The lock must not already be held by the current
thread.

This function will not sleep, so it may be called within an
interrupt handler. */
bool lock_try_acquire(struct lock *lock) {
    bool success;

    ASSERT(lock != NULL);
    ASSERT(!lock_held_by_current_thread(lock));

    success = sema_try_down(&lock->semaphore);
    if (success)
        lock->holder = thread_current();
    return success;
}

/* Releases LOCK, which must be owned by the current thread.
This is lock_release function.

An interrupt handler cannot acquire a lock, so it does not
make sense to try to release a lock within an interrupt
handler. */
void lock_release(struct lock *lock) {
    ASSERT(lock != NULL);
    ASSERT(lock_held_by_current_thread(lock));
    struct thread *t = thread_current();
    enum intr_level old_level = intr_disable();
    remove_donations(lock, t);
    if (!list_empty(&t->donation_list)) {
        t->priority = get_high_donation(t);
    } else {
        t->priority = t->o_priority;
    }

    lock->holder = NULL;
    sema_up(&lock->semaphore);
    intr_set_level(old_level);
}

/* Returns true if the current thread holds LOCK, false
otherwise.  (Note that testing whether some other thread holds
a lock would be racy.) */
bool lock_held_by_current_thread(const struct lock *lock) {
    ASSERT(lock != NULL);

    return lock->holder == thread_current();
}

/* One semaphore in a list. */
struct semaphore_elem {
    struct list_elem elem;           /* List element. */
    struct semaphore semaphore;      /* This semaphore. */
    struct thread *matching_thread;  // 추가
};

/* Initializes condition variable COND.  A condition variable
allows one piece of code to signal a condition and cooperating
code to receive the signal and act upon it. */
void cond_init(struct condition *cond) {
    ASSERT(cond != NULL);

    list_init(&cond->waiters);
}

/* Atomically releases LOCK and waits for COND to be signaled by
some other piece of code.  After COND is signaled, LOCK is
reacquired before returning.  LOCK must be held before calling
this function.

The monitor implemented by this function is "Mesa" style, not
"Hoare" style, that is, sending and receiving a signal are not
an atomic operation.  Thus, typically the caller must recheck
the condition after the wait completes and, if necessary, wait
again.

A given condition variable is associated with only a single
lock, but one lock may be associated with any number of
condition variables.  That is, there is a one-to-many mapping
from locks to condition variables.

This function may sleep, so it must not be called within an
interrupt handler.  This function may be called with
interrupts disabled, but interrupts will be turned back on if
we need to sleep. */
void cond_wait(struct condition *cond, struct lock *lock) {
    struct semaphore_elem waiter;

    ASSERT(cond != NULL);
    ASSERT(lock != NULL);
    ASSERT(!intr_context());
    ASSERT(lock_held_by_current_thread(lock));
    sema_init(&waiter.semaphore, 0);
    waiter.matching_thread = thread_current();
    list_insert_ordered(&cond->waiters, &waiter.elem, higher_priority_sema, NULL);
    lock_release(lock);
    sema_down(&waiter.semaphore);
    lock_acquire(lock);
}

/* If any threads are waiting on COND (protected by LOCK), then
this function signals one of them to wake up from its wait.
LOCK must be held before calling this function.

An interrupt handler cannot acquire a lock, so it does not
make sense to try to signal a condition variable within an
interrupt handler. */
void cond_signal(struct condition *cond, struct lock *lock UNUSED) {
    ASSERT(cond != NULL);
    ASSERT(lock != NULL);
    ASSERT(!intr_context());
    ASSERT(lock_held_by_current_thread(lock));

    if (!list_empty(&cond->waiters)) {
        sema_up(
            &list_entry(list_pop_front(&cond->waiters), struct semaphore_elem, elem)->semaphore);
    }
}

/* Wakes up all threads, if any, waiting on COND (protected by
LOCK).  LOCK must be held before calling this function.

An interrupt handler cannot acquire a lock, so it does not
make sense to try to signal a condition variable within an
interrupt handler. */
void cond_broadcast(struct condition *cond, struct lock *lock) {
    ASSERT(cond != NULL);
    ASSERT(lock != NULL);

    while (!list_empty(&cond->waiters)) cond_signal(cond, lock);
}

static bool higher_priority_sema(const struct list_elem *a_, const struct list_elem *b_,
                                 void *aux UNUSED) {
    const struct thread *a = list_entry(a_, struct semaphore_elem, elem)->matching_thread;
    const struct thread *b = list_entry(b_, struct semaphore_elem, elem)->matching_thread;

    return a->priority > b->priority;
}
