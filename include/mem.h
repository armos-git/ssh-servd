#ifndef MEM_H
#define MEM_H

/* Safe free! */
#define	memfree(p)	{ if ((p) != NULL) free(p); }

extern	void	*memalloc(size_t size);

#endif /* MEM_H */
