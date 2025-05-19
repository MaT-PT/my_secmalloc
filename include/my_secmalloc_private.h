#ifndef _SECMALLOC_PRIVATE_H
#define _SECMALLOC_PRIVATE_H
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#if DYNAMIC
#define MY static
#else
#define MY
#endif

/*
 * Ici vous pourrez faire toutes les déclarations de variables/fonctions pour votre usage interne
 * */

#ifndef MAP_ANON
// Ensure MAP_ANON is defined
#define MAP_ANON MAP_ANONYMOUS
#endif

#define trace_to_file(fmt, args...)                                                                \
    do {                                                                                           \
        my_log_to_file("%s:%03d:%24s: " fmt "\n", __FILE__, __LINE__, __func__, ##args);           \
    }                                                                                              \
    while (0)

#ifdef DEBUG
#define debug_print(fmt, args...)                                                                  \
    do {                                                                                           \
        my_log("[DEBUG my_secmalloc] " fmt "\n", ##args);                                          \
    }                                                                                              \
    while (0)
#else
#define debug_print(fmt, ...)                                                                      \
    do {                                                                                           \
    }                                                                                              \
    while (0)
#endif

#define EXIT_INVALID_PTR 100
#define EXIT_BAD_CANARY  101
#define EXIT_DOUBLE_FREE 102

typedef struct block_metadata_tag block_metadata_t;

struct block_metadata_tag {
    size_t p_data_offset; // relative offset from p_data_pool
    bool b_is_busy;       // false if free, true if busy
    size_t sz_size;       // size of the block in bytes, not including canary. 0 iff uninitialized
    uint64_t ui64_canary; // canary value
    block_metadata_t *p_prev; // previous block in the list
    block_metadata_t *p_next; // next block in the list
};

#define PAGE_SHIFT    12
#define PAGE_SIZE     (1UL << PAGE_SHIFT)
#define PAGE_MASK     (PAGE_SIZE - 1)
#define PAGE_ALIGN(x) (((x) + PAGE_MASK) & ~PAGE_MASK)

#define CANARY_SIZE    (sizeof(((block_metadata_t *)0)->ui64_canary))
#define METADATA_SIZE  (sizeof(block_metadata_t))
#define N_META_SIZE(n) ((n)*METADATA_SIZE)

MY uint64_t get_random_canary();

MY void check_memory_leaks();

MY bool check_init_pools();

MY void expand_data_pool(size_t sz_new_size);

MY void expand_meta_pool();

MY block_metadata_t *find_uninitialized_block();

MY block_metadata_t *find_block_from_ptr(void *p_data_ptr);

MY block_metadata_t *find_busy_block_from_ptr(void *p_data_ptr);

MY block_metadata_t *
allocate_after(block_metadata_t *p_block, size_t sz_size, bool b_update_canary);

MY void split_block(block_metadata_t *p_block, size_t sz_size);

MY void merge_block(block_metadata_t *p_block);

MY block_metadata_t *find_fitting_block(size_t sz_size);

MY bool my_log(const char *s_fmt, ...) __attribute__((__format__(__printf__, 1, 2)));

MY bool my_log_trace(const char *s_fmt, ...) __attribute__((__format__(__printf__, 1, 2)));

MY bool my_log_to_file(const char *s_fmt, ...) __attribute__((__format__(__printf__, 1, 2)));

MY bool my_vlog(const int fd, const char *s_fmt, va_list args)
    __attribute__((__format__(__printf__, 2, 0)));

MY bool my_vlog_to_file(const char *s_fmt, va_list args)
    __attribute__((__format__(__printf__, 1, 0)));

MY void print_block(block_metadata_t *p_block);

MY void __attribute__((__unused__)) print_block_list();

MY void __attribute__((__unused__)) print_all_blocks();

MY void *check_canary_worker();

#endif
