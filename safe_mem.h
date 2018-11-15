#ifndef SAFEMEM_H
#define SAFEMEM_H

void *_alloc_safe_mem(size_t req_sz, const char *file, int line);
void *_strdup_safe_mem(const char *in, const char *file, int line);
void _free_safe_mem(void *mem, const char *file, int line);
void check_and_purge_safe_mem(void);
int enable_safe_mem_global_lock(void);

#ifndef __DECONST
#define __DECONST(type, var)    ((type)(uintptr_t)(const void *)(var))
#endif

#define alloc_safe_mem(x) \
    _alloc_safe_mem(x, __FILE__, __LINE__)

#define alloc_safe_mem_1(x) \
    _alloc_safe_mem(x, __FILE__, __LINE__ * -1)

#define strdup_safe_mem(x) \
    _strdup_safe_mem(x, __FILE__, __LINE__)

#define free_safe_mem(x) \
    _free_safe_mem(__DECONST(void *, x), __FILE__, __LINE__)


#endif
