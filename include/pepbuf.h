/* PEPsal : A Performance Enhancing Proxy for Satellite Links
 *
 * Copyleft Daniele Lacamera 2005
 * Copyleft Dan Kruchining <dkruchinin@google.com> 2010
 * See AUTHORS and COPYING before using this software.
 *
 *
 *
 */

#ifndef __PEPBUF_H
#define __PEPBUF_H

#include <sys/types.h>
#include "pepdefs.h"

struct pep_buffer {
    void *space;
    char *r_pos;
    char *w_pos;
    size_t rbytes;
    size_t space_left;
    size_t total_size;
};

#define pepbuf_empty(pbuf)       ((pbuf)->rbytes == 0)
#define pepbuf_full(pbuf)        ((pbuf)->space_left == 0)
#define pepbuf_initialized(pbuf) ((pbuf)->space != NULL)

#define PEPBUF_RPOS(pbuf)         (pbuf)->r_pos
#define PEPBUF_WPOS(pbuf)         (pbuf)->w_pos
#define PEPBUF_SPACE_LEFT(pbuf)   (pbuf)->space_left
#define PEPBUF_SPACE_FILLED(pbuf) (pbuf)->rbytes

int pepbuf_init(struct pep_buffer *pbuf);
void pepbuf_deinit(struct pep_buffer *pbuf);
void pepbuf_update_rpos(struct pep_buffer *pbuf, ssize_t rb);
void pepbuf_update_wpos(struct pep_buffer *pbuf, ssize_t wb);

#endif /* __PEPBUF_H */
