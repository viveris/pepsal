#ifndef __PEPSDEFS_H
#define __PEPSDEFS_H

#include <sys/user.h>

/* Minimal and maximal number of simultaneous connections */
#define PEP_MIN_CONNS 128
#define PEP_MAX_CONNS 4096

/* Default port number of pepsal listener */
#define PEP_DEFAULT_PORT 5000

/* Default receive buffer size of queuer thread */
#define QUEUER_BUF_SIZE PAGE_SIZE

/*
 * Size of buffer that is used for temporary error messages
 * composed by pep_error and pep_warning functions.
 */
#define PEP_ERRBUF_SZ 1024

/* Queue size of listener thread used for incomming TCP packets */
#define LISTENER_QUEUE_SIZE 60000

/*
 * Signal number that is sent to poller thread when
 * new incomming connection appears
 */
#define POLLER_NEWCONN_SIG SIGUSR1

/* Number of pages reserved for send/receive buffers */
#define PEPBUF_PAGES 2

/* Number of worker threads in pepsal threads pool */
#define PEPPOOL_THREADS 10

#define PEPLOGGER_INTERVAL (5 * 60)

#define PEP_GCC_INTERVAL (15 * 3600)

#define PEP_PENDING_CONN_LIFETIME (5 * 3600)

#ifndef offsetof
#define offsetof(type, field)                               \
    ((size_t)&(((type *)0)->field) - (size_t)((type *)0))
#endif /* !offsetof */

#define container_of(ptr, type, member)                 \
    (type *)((char *)(ptr) - offsetof(type, member))

#endif /* !_PEPSDEFS_H */
