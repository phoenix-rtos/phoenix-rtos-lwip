/*
 * Phoenix-RTOS --- LwIP port
 *
 * Copyright 2015 Phoenix Systems
 * Author: Michal Wojcikowski
 *
 * %LICENSE%
 */

#ifndef LIB_LIST_H_
#define LIB_LIST_H_

#define LIST_ENTRY(type) \
	struct { \
		struct type *next, *prev; \
	}

#define LIST_HEAD(type) \
	struct { \
		struct type *first; \
	}

#define LIST_HEAD_INITIALIZER \
	{ \
		NULL \
	}
#define LIST_HEAD_INIT(head) \
	do { \
		(head)->first = NULL; \
	} while (0)
#define LIST_ELEM_INIT(elem, field) \
	do { \
		(elem)->field.next = (elem)->field.prev = elem; \
	} while (0)

#define LIST_ENTRY_INITIALIZER \
	{ \
		NULL, NULL \
	}
#define LIST_ENTRY_INIT(elem) \
	do { \
		(elem)->next = (elem)->prev = NULL; \
	} while (0)

#define LIST_IS_EMPTY(head) ((head)->first == NULL)

/* add list using first list element as list handler. List must be not empty */
#define LIST_ADD_ELEM(first, elem, field) \
	do { \
		elem->field.prev = first->field.prev; \
		elem->field.next = first; \
		first->field.prev->field.next = elem; \
		first->field.prev = elem; \
	} while (0)

/* add using list head */
#define LIST_ADD(head, elem, field) \
	do { \
		if ((head)->first) \
			LIST_ADD_ELEM((head)->first, (elem), field); \
		else { \
			(head)->first = elem; \
			(elem)->field.next = (elem)->field.prev = elem; \
		} \
	} while (0)

#define LIST_REMOVE(head, elem, field) \
	do { \
		(elem)->field.prev->field.next = (elem)->field.next; \
		(elem)->field.next->field.prev = (elem)->field.prev; \
		if ((head)->first == (elem)) { \
			if ((elem)->field.next == (elem)) \
				(head)->first = NULL; \
			else if ((head)->first == elem) \
				(head)->first = (elem)->field.next; \
		} \
	} while (0)

#define LIST_MERGE(h1, h2, field) \
	do { \
		if (!(h1)->first) { \
			(h1)->first = (h2)->first; \
		} \
		else if (!(h2)->first) { \
			break; \
		} \
		else { \
			typeof((h1)->first) h1tail = (h1)->first->field.prev; \
			typeof((h2)->first) h2tail = (h2)->first->field.prev; \
			h1tail->field.next = (h2)->first; \
			h2tail->field.next = (h1)->first; \
			(h1)->first->field.prev = h2tail; \
			(h2)->first->field.prev = h1tail; \
		} \
		(h2)->first = NULL; \
	} while (0)


/* 
 * */
#define LIST_DISAPEAR(elem, field) \
	do { \
		(elem)->field.prev->field.next = NULL; \
		(elem)->field.next->field.prev = NULL; \
		LIST_ELEM_INIT(elem, field); \
	} while (0)

#define LIST_FIND(head, iter, field, pred) \
	do { \
		u8 found = 0; \
		(iter) = (head)->first; \
		if (iter != NULL) { \
			do { \
				if (pred) { \
					found = 1; \
					break; \
				} \
				(iter) = (iter)->field.next; \
			} while ((iter) != (head)->first); \
		} \
		if (found == 0) \
			iter = NULL; \
	} while (0)


#define LIST_FOR_EACH(head, iter, field) \
	for (iter = (head)->first; \
		 iter != NULL; \
		 iter = (iter->field.next == (head)->first) ? NULL : iter->field.next)

#endif
