
/*
 * PEPsal : A Performance Enhancing Proxy for Satellite Links
 *
 * Copyleft Dan Kruchinin <dkruchinin@google.com> 2010
 * See AUTHORS and COPYING before using this software.
 *
 *
 *
 */

#ifndef __PEPQUEUE_H
#define __PEPQUEUE_H

#include <pthread.h>
#include "pepdefs.h"
#include "list.h"

struct pep_queue {
    struct list_head queue;
    int num_items;
    pthread_mutex_t mutex;
    pthread_cond_t condvar;
};

#define PEPQUEUE_LOCK(pq)   pthread_mutex_lock(&(pq)->mutex)
#define PEPQUEUE_UNLOCK(pq) pthread_mutex_unlock(&(pq)->mutex)

#define PEPQUEUE_WAKEUP_WAITERS(pq) pthread_cond_signal(&(pq)->condvar)
#define PEPQUEUE_WAIT(pq) pthread_cond_wait(&(pq)->condvar, &(pq)->mutex)

int pepqueue_init(struct pep_queue *pq);
void pepqueue_enqueue(struct pep_queue *pq, struct pep_proxy *endp);
void pepqueue_enqueue_list(struct pep_queue *pq,
                          struct list_head *list, int num_items);
struct pep_proxy *pepqueue_dequeue(struct pep_queue *pq);
void pepqueue_dequeue_list(struct pep_queue *pq, struct list_head *list);

#endif /* __PEPQUEUE_H */
