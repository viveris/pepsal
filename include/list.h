/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 *
 * (c) Copyright 2008 Dan Kruchinin <dkruchinin@google.com>
 */

#ifndef __LIST_H__
#define __LIST_H__

#include <stddef.h>
#include "pepdefs.h"

/**
 * @struct list_node
 * @brief List node
 */
struct list_node {
    struct list_node *next;
    struct list_node *prev;
};

/**
 * @struct list_head
 * @brief List head
 * Actually struct list_head is the same as struct list_node, but
 * they have different types though. That was done to prevent
 * potentional errors(notice that list head is a stub, it's never
 * tied with any real data and it's used only to determine where list
 * starts and where it ends)
 */
struct list_head {
    struct list_node head; /**< Head element of the list */
};


/**
 * @def LIST_DEFINE(name)
 * @brief Define and initialize list head with name @a name
 * @param name - name of variable
 */
#define LIST_DEFINE(name)                           \
    struct list_head (name) = LIST_INITIALIZE(name)

/**
 * @def LIST_INITIALIZE
 * @brief Initialize list head.
 * @param name - list name
 */
#define LIST_INITIALIZE(name)                   \
    { .head = { &(name).head, &(name).head } }

#define list_node2head(node)                    \
    ((struct list_head *)(node))

/**
 * @fn static __inline void list_init_head(struct list_head *lst)
 * @brief Initialize list head
 * @param lst - a pointer to list head.
 */
static __inline void list_init_head(struct list_head *lst)
{
    lst->head.next = lst->head.prev = &lst->head;
}

/**
 * @fn static __inline void list_init_node(struct list_node *node)
 * @brief Initialize list node
 * @param node - a pointer to free(unattached from list) node.
 */
static __inline void list_init_node(struct list_node *node)
{
    node->next = NULL;
    node->prev = NULL;
}

static __inline int list_node_next_isbound(struct list_node *node)
{
    return (node->next != NULL);
}

static __inline int list_node_prev_isbound(struct list_node *node)
{
    return (node->prev != NULL);
}

#define list_node_is_bound(node)                                    \
    (list_node_next_isbound(node) && list_node_prev_isbound(node))

/**
 * @def list_entry(lst, nptr)
 * @brief Get item that holds @a nptr node
 * @param list - A pointer to the list
 * @param nptr - A pointer to the node
 * @return A pointer to the object given node contains
 */
#define list_entry(node, type, member)          \
    container_of(node, type, member)

/**
 * @def list_head(lst)
 * @brief Get head of the list
 * @param lst - a pointer to struct list_head
 * @return A pointer to header struct list_node
 */
#define list_head(lst)                          \
    (&(lst)->head)

/**
 * @def list_node_first(lst)
 * @brief Get list's first node
 * @param list - A pointer to the struct list_head
 * @return A pointer to the list first node
 */
#define list_node_first(lst)                    \
    ((lst)->head.next)

/**
 * @def list_node_last(lst)
 * @brief Get list's last node
 * @param list - A pointer to the struct list_head
 * @return A pointer to the list last node
 */
#define list_node_last(lst)                     \
    ((lst)->head.prev)

/**
 * @def list_add2head(lst, new)
 * @brief Add a node @a new to the head of the list
 * @param lst - A pointer to the list
 * @param new - A pointer to the list node
 */
#define list_add2head(lst, new)                 \
    list_add_before(list_node_first(lst), new)

/**
 * @def list_add2tail(lst, new)
 * @brief Add a node @a new to the tail of the list
 * @param lst - A pointer to the list
 * @param new - A pointer to node to add
 */
#define list_add2tail(lst, new)                 \
    list_add_before(list_head(lst), new)

/**
 * @def list_delfromhead(lst)
 * @brief Remove first element of the list
 * @param lst - A pointer to the list
 */
#define list_delfromhead(lst)					\
    list_del(list_node_first(lst))

/**
 * @def list_delfromtail(lst)
 * @brief Remove the last element of the list
 * @param list - A pointer to the list
 */
#define list_delfromtail(lst)					\
    list_del(list_node_last(lst))

/**
 * @def list_del(del)
 * @brief Remove node @a del from the list
 * @param del - A node to remove
 */
#define list_del(del)                           \
    (list_del_range(del, del))

/**
 * @def list_add_before(before, new)
 * @param brefore - The node before which @a new will be inserted
 * @param new     - A node to insert
 */
#define list_add_before(before, new)                    \
    (list_add_range(new, new, (before)->prev, before))

/**
 * @def list_add_after(after, new)
 * @param after - The node after which a new one will be inserted
 * @param new   - A node to insert
 */
#define list_add_after(after, new)                      \
    (list_add_range(new, new, (after), (after)->next))

/**
 * @def list_move2head(to, from)
 * @brief Move all nodes from list @a from to the head of list @a to
 * @param to   - destination list
 * @param from - source list
 */
#define list_move2head(to, from)                            \
    (list_move(list_head(to), list_node_first(to), from))

/**
 * @def list_move2tail(to, from)
 * @brief Move all nodes from list @a from to the tail of list @a to
 * @param to   - destination list
 * @param from - source list
 */
#define list_move2tail(to, from)                            \
    (list_move(list_node_last(to), list_head(to), from))

/**
 * @def list_for_each(lst, liter)
 * @brief Iterate through each element of the list
 * @param lst   - A pointer to list head
 * @param liter - A pointer to list which will be used for iteration
 */
#define list_for_each(lst, liter)                               \
    for (liter = list_node_first(lst);                          \
         (liter) != list_head(lst); (liter) = (liter)->next)

/**
 * @def list_for_each_safe(lst, liter, save)
 * @brief Safe iteration through the list @a lst
 *
 * This iteration wouldn't be broken even if @a liter will be removed
 * from the list
 *
 * @param lst   - A pointer to the list head
 * @param liter - A pointer to list node which will be used for iteration
 * @param save  - The same
 */
#define list_for_each_safe(lst, liter, save)                    \
    for (liter = list_node_first(lst), save = (liter)->next;    \
         (liter) != list_head(lst); (liter) = (save),           \
             (save) = (liter)->next)

/**
 * @def list_for_each_entry(lst, iter, member)
 * @brief Iterate through each list node member
 * @param lst    - a pointer list head
 * @param iter   - a pointer to list entry using as iterator
 * @param member - name of list node member in the parent structure
 */
#define list_for_each_entry(lst, iter, type, member)                    \
    for (iter = list_entry(list_node_first(lst), type, member); \
         &iter->member != list_head(lst);                               \
         iter = list_entry(iter->member.next, type, member))


/**
 * @fn static __inline int list_is_empty(list_t *list)
 * @brief Determines if list @a list is empty
 * @param list - A pointer to list to test
 * @return True if list is empty, false otherwise
 */
static __inline int list_is_empty(struct list_head *list)
{
    return (list_node_first(list) == list_head(list));
}

/**
 * @fn static __inline void list_add_range(struct list_node *first,
 *                                       struct list_node *last,
 *                                       struct list_node *prev,
 *                                       struct list_node *next)
 * @brief Insert a range of nodes from @a frist to @a last after
 *        @a prev and before @a next
 * @param first - first node of range
 * @param last  - last node of range
 * @param prev  - after this node a range will be inserted
 * @param next  - before this node a range will be inserted 
 */
static __inline void list_add_range(struct list_node *first,
                                    struct list_node *last,
                                    struct list_node *prev,
                                    struct list_node *next)
{
    first->prev = prev;
    last->next = next;
    next->prev = last;
    prev->next = first;
}

/* for internal usage */
static __inline void __list_del_range(struct list_node *first,
                                    struct list_node *last)
{
    first->prev->next = last->next;
    last->next->prev = first->prev;
}

/**
 * @fn static __inline list_del_range(struct list_node *first,
 *                                  struct list_node *last)
 * @brief Delete nodes from @a first to @a last from list.
 * @param fist - first node to delete
 * @param last - last node to delete
 */
static __inline void list_del_range(struct list_node *first,
                                  struct list_node *last)
{
    __list_del_range(first, last);
    first->prev = NULL;
    last->next = NULL;
}

/**
 * @fn static __inline void list_cut_sublist(struct list_node *first,
 *                                         struct list_node *last)
 * @brief Cut a "sublist" started from @a first and ended with @a last
 *
 * A @e "sublist" is similar to ordinary list except it hasn't a head.
 * In other words it's a cyclic list in which all nodes are equitable.
 *
 * @param first - From this node sublist will be cutted
 * @param last  - The last node in the cutted sequence
 */
static __inline void list_cut_sublist(struct list_node *first,
                                    struct list_node *last)
{
    __list_del_range(first, last);
    first->prev = last;
    last->next = first;
}

/**
 * @fn static __inline void list_cut_head(struct list_head *head)
 * @brief Cut a head from the list and make a "sublist"
 * @param head - List's head that will be cutted.
 * @see list_cut_sublist
 * @see list_set_head
 */
static __inline void list_cut_head(struct list_head *head)
{
    list_cut_sublist(list_node_first(head), list_node_last(head));
}

/**
 * @fn static __inline void list_cut_head(struct list_head *head)
 * @brief Attach a head to the sublist @a cyclist
 * @param new_head - A head that will be attached
 * @param cyclist  - "sublist"
 * @see list_cut_sublist
 * @see list_set_head
 */
static __inline void list_set_head(struct list_head *new_head,
                                 struct list_node *cyclist)
{
    list_add_range(cyclist, cyclist->prev,
                   list_node_first(new_head), list_node_last(new_head));
}

/**
 * @fn static __inline void list_move(struct list_node *prev,
 *                                  struct list_node *next,
 *                                  struct list_head *from)
 * @brief Insert nodes of list @a from after @a prev and before @a next
 * @param prev - a node after which nodes of @a from will be inserted
 * @param next - a node before which nodes of @a from will be inserted
 */
static __inline void list_move(struct list_node *prev,
                               struct list_node *next,
                               struct list_head *from)
{
    list_add_range(list_node_first(from), list_node_last(from),
                   prev, next);
    list_init_head(from);
}

#endif /* __LIST_H__ */

