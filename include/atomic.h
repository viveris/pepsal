#ifndef __ATOMIC_H
#define __ATOMIC_H

#ifndef __GNUC__
#error "Atomic operations require GCC compiler!"
#endif /* !GCC */

typedef struct __atomic {
    volatile int val;
} atomic_t;

#define atomic_read(a)   ((a)->val)
#define atomic_set(a, b) ((a)->val = b)

static inline int atomic_inc(atomic_t *a)
{
    return __sync_fetch_and_add(&a->val, 1);
}

static inline int atomic_dec(atomic_t *a)
{
    return __sync_fetch_and_sub(&a->val, 1);
}

static inline int atomic_and(atomic_t *a, int mask)
{
    return __sync_fetch_and_and(&a->val, mask);
}

static inline int atomic_or(atomic_t *a, int mask)
{
    return __sync_fetch_and_or(&a->val, mask);
}

#endif /* __ATOMIC_H */
