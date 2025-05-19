// cette définition permet d'accéder à mremap lorsqu'on inclue sys/mman.h
#define _GNU_SOURCE
#include "my_secmalloc.h"
#include <alloca.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include "my_secmalloc_private.h"

#define START_ADDRESS_META (void *)0x0000100000000000
#define START_ADDRESS_DATA (void *)0x0000200000000000

static void *p_data_pool             = NULL;
static block_metadata_t *p_meta_pool = NULL;
static size_t sz_data_pool_size      = 32 * PAGE_SIZE;
static size_t sz_meta_pool_count     = 32;
static bool b_is_initialized         = false;

// Generate a random 64-bit canary value using rand(), taking 4 blocks of 16 random bits
uint64_t get_random_canary() {
    uint64_t canary = 0;
    for (size_t i = 0; i < sizeof(canary); i += 2) {
        canary = (canary << 16) | (rand() & 0xFFFFU);
    }

    if (canary == 0) {
        // 0 is not a valid canary value, generate a new one
        return get_random_canary();
    }
    return canary;
}

// Return a pointer to the data of the given block
static inline void *get_block_data_ptr(block_metadata_t *p_block) {
    return (char *)p_data_pool + p_block->p_data_offset;
}

// Return a pointer to the canary of the given block
static inline uint64_t *get_block_canary_ptr(block_metadata_t *p_block) {
    return (uint64_t *)((char *)p_data_pool + p_block->p_data_offset + p_block->sz_size);
}

// Update the canary of the given block with the value stored in the block
static inline void update_block_canary(block_metadata_t *p_block) {
    *get_block_canary_ptr(p_block) = p_block->ui64_canary;
}

// Return true if the canary is valid, false otherwise
static inline bool check_canary(block_metadata_t *p_block) {
    return p_block->ui64_canary == *get_block_canary_ptr(p_block);
}

// Shrink the block, splitting it if possible, set it as busy, and update the canary
static inline void resize_block(block_metadata_t *p_block, size_t sz_new_size) {
    trace_to_file("> Resizing block at %p to %zu B...", p_block, sz_new_size);
    if (p_block->sz_size > sz_new_size + CANARY_SIZE) {
        split_block(p_block, sz_new_size);
    }
    p_block->b_is_busy   = true;
    p_block->sz_size     = sz_new_size;
    p_block->ui64_canary = get_random_canary();
    update_block_canary(p_block);
}

// Return the last block in the metadata pool list
static inline block_metadata_t *get_last_block() {
    trace_to_file("> Getting last block...");
    block_metadata_t *p_block = p_meta_pool;
    while (p_block->p_next != NULL) {
        p_block = p_block->p_next;
    }

    trace_to_file("Last block is at %p", p_block);
    return p_block;
}

// Insert a new block after the given block in the metadata pool list
static inline void insert_block_after(block_metadata_t *p_block, block_metadata_t *p_new_block) {
    if (p_block == p_new_block) {
        // Don't insert the block after itself
        return;
    }

    p_new_block->p_prev = p_block;
    p_new_block->p_next = p_block->p_next;
    if (p_block->p_next != NULL) {
        p_block->p_next->p_prev = p_new_block;
    }
    p_block->p_next = p_new_block;
}

// Remove a block from the metadata pool list, and reset its fields
static inline void remove_block(block_metadata_t *p_block) {
    if (p_block->p_prev != NULL) {
        p_block->p_prev->p_next = p_block->p_next;
    }
    if (p_block->p_next != NULL) {
        p_block->p_next->p_prev = p_block->p_prev;
    }

    p_block->sz_size = 0;
    p_block->p_next  = NULL;
    p_block->p_prev  = NULL;
}

// Check for memory leaks and print a warning if any are found
void check_memory_leaks() {
    trace_to_file("> Checking for memory leaks...");
    block_metadata_t *p_block = p_meta_pool;
    while (p_block != NULL) {
        if (p_block->b_is_busy) {
            trace_to_file("--------------------------------");
            trace_to_file(
                "WARNING: Memory leak: block not freed at %p", get_block_data_ptr(p_block));
            print_block(p_block);
        }
        p_block = p_block->p_next;
    }
}

bool check_init_pools() {
    if (b_is_initialized) {
        // Already initialized, nothing to do
        return true;
    }

    trace_to_file("> Initializing pools...");

    p_meta_pool = mmap(
        START_ADDRESS_META, N_META_SIZE(sz_meta_pool_count), PROT_READ | PROT_WRITE,
        MAP_ANON | MAP_PRIVATE, -1, 0);
    if (p_meta_pool == MAP_FAILED || p_meta_pool == NULL) {
        my_log_trace("ERROR: Failed allocating metadata pool\n");
        return false;
    }

    p_data_pool = mmap(
        START_ADDRESS_DATA, sz_data_pool_size, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1,
        0);
    if (p_data_pool == MAP_FAILED || p_data_pool == NULL) {
        my_log_trace("ERROR: Failed allocating data pool\n");
        return false;
    }

    b_is_initialized = true;

    atexit(check_memory_leaks);

    pthread_t thd_check_canary;
    pthread_create(&thd_check_canary, NULL, check_canary_worker, NULL);

    return true;
}

// Expand the data pool if necessary, aligning the new size to a page boundary
void expand_data_pool(size_t sz_new_size) {
    if (sz_new_size <= sz_data_pool_size) {
        return;
    }

    trace_to_file("> Not enough space in p_data_pool, need to allocate new pages");

    size_t sz_new_size_align = PAGE_ALIGN(sz_new_size);
    trace_to_file("Old size: %zu, new size: %zu", sz_data_pool_size, sz_new_size_align);

    p_data_pool       = mremap(p_data_pool, sz_data_pool_size, sz_new_size_align, 0);
    sz_data_pool_size = sz_new_size_align;
}

// Expand the metadata pool size by doubling it
void expand_meta_pool() {
    trace_to_file("> Not enough space in p_meta_pool, doubling its size");

    size_t sz_new_count = sz_meta_pool_count * 2;
    size_t sz_old_size  = N_META_SIZE(sz_meta_pool_count);
    size_t sz_new_size  = N_META_SIZE(sz_new_count);
    trace_to_file(
        "Old count: %zu (%zu B), new count: %zu (%zu B)", sz_meta_pool_count, sz_old_size,
        sz_new_count, sz_new_size);

    p_meta_pool        = mremap(p_meta_pool, sz_old_size, sz_new_size, 0);
    sz_meta_pool_count = sz_new_count;
}

// Find the first uninitialized block in the metadata pool, expanding it if necessary
block_metadata_t *find_uninitialized_block() {
    trace_to_file("> Looking for first uninitialized block in p_meta_pool...");
    block_metadata_t *p_current     = p_meta_pool;
    block_metadata_t *sz_meta_limit = p_meta_pool + sz_meta_pool_count;

    while (p_current < sz_meta_limit) {
        if (p_current->sz_size == 0) {
            trace_to_file("First uninitialized block: %p", p_current);
            return p_current;
        }
        p_current++;
    }

    // No uninitialized block found, expand the pool
    size_t sz_old_count = sz_meta_pool_count;
    expand_meta_pool();
    if (p_meta_pool == MAP_FAILED) {
        my_log_trace("ERROR: Failed reallocating p_meta_pool\n");
        return NULL;
    }

    trace_to_file("First uninitialized block: %p", p_meta_pool + sz_old_count);
    return p_meta_pool + sz_old_count;
}

// Find the metadata block corresponding to the given data pointer
block_metadata_t *find_block_from_ptr(void *p_data_ptr) {
    block_metadata_t *p_current = p_meta_pool;

    while (p_current != NULL) {
        if (get_block_data_ptr(p_current) == p_data_ptr) {
            return p_current;
        }
        p_current = p_current->p_next;
    }

    trace_to_file("ERROR: Failed finding block for pointer %p", p_data_ptr);
    return NULL;
}

// Find the metadata block corresponding to the given data pointer, and exit if
// the block is not found, is not busy, or the canary is invalid
block_metadata_t *find_busy_block_from_ptr(void *p_data_ptr) {
    block_metadata_t *p_block = find_block_from_ptr(p_data_ptr);

    if (p_block == NULL) {
        my_log_trace("ERROR: Block not found for address: %p\n", p_data_ptr);
        _exit(EXIT_INVALID_PTR);
    }

    if (!p_block->b_is_busy) {
        my_log_trace("ERROR: Double free detected\n");
        _exit(EXIT_DOUBLE_FREE);
    }

    if (!check_canary(p_block)) {
        my_log_trace("ERROR: Heap overflow (corrupted canary)\n");
        _exit(EXIT_BAD_CANARY);
    }

    return p_block;
}

// Allocate a new block of sz_size bytes after the given block, expanding the data pool if necessary
// Returns the new block, or NULL if the allocation failed
block_metadata_t *allocate_after(block_metadata_t *p_block, size_t sz_size, bool b_update_canary) {
    trace_to_file("> Allocating new block after %p, requested %zu B", p_block, sz_size);

    block_metadata_t *p_new_block = find_uninitialized_block();

    if (p_new_block == NULL) {
        my_log_trace("ERROR: Failed allocating new block\n");
        return NULL;
    }

    size_t sz_new_offset;

    trace_to_file("p_block->p_prev: %p", p_block->p_prev);
    trace_to_file("p_block->sz_size: %zu", p_block->sz_size);

    if (p_block->p_prev == NULL && p_block->sz_size == 0) {
        // First block in the list, allocate at the beginning of the data pool
        trace_to_file("First allocation");
        sz_new_offset = 0;
    }
    else {
        // Allocate after the previous block
        trace_to_file("Not first allocation");
        sz_new_offset = p_block->p_data_offset + p_block->sz_size + CANARY_SIZE;
    }
    trace_to_file("sz_new_offset: %zu", sz_new_offset);

    insert_block_after(p_block, p_new_block);
    expand_data_pool(sz_new_offset + sz_size + CANARY_SIZE);
    if (p_data_pool == MAP_FAILED) {
        my_log_trace("ERROR: Failed reallocating p_data_pool\n");
        return NULL;
    }

    p_new_block->p_data_offset = sz_new_offset;
    p_new_block->sz_size       = sz_size;

    if (b_update_canary) {
        p_new_block->ui64_canary = get_random_canary();
        update_block_canary(p_new_block);
    }

    trace_to_file("New block at %p, offset %zu, size %zu", p_new_block, sz_new_offset, sz_size);
    return p_new_block;
}

// Split the given block into two blocks, the first one being the requested size
void split_block(block_metadata_t *p_block, size_t sz_size) {
    trace_to_file("> Splitting block at %p, requested %zu B", p_block, sz_size);

    size_t sz_size_with_canary = sz_size + CANARY_SIZE;

    if (p_block->sz_size <= sz_size_with_canary) {
        trace_to_file(
            "ERROR: Block too small to split: size is %zu B, we need at least %zu B with canary",
            p_block->sz_size, sz_size_with_canary);
        return;
    }

    size_t sz_new_size            = p_block->sz_size - sz_size_with_canary;
    block_metadata_t *p_new_block = allocate_after(p_block, sz_new_size, false);

    if (p_new_block == NULL) {
        trace_to_file("ERROR: Failed allocating new block");
        return;
    }

    p_new_block->p_data_offset = p_block->p_data_offset + sz_size_with_canary;
    p_new_block->b_is_busy     = false;
    p_block->sz_size           = sz_size;

    // Merge new block with the next one if possible
    if (p_new_block->p_next != NULL && !p_new_block->p_next->b_is_busy) {
        trace_to_file("Merging with next block");
        merge_block(p_new_block);
    }
}

// Merge the given block with the next one
void merge_block(block_metadata_t *p_block) {
    trace_to_file("> Merging block at %p", p_block);

    block_metadata_t *p_next_block = p_block->p_next;

    if (p_next_block == NULL) {
        trace_to_file("ERROR: Block is the last one, can't merge");
        return;
    }

    if (p_next_block->b_is_busy) {
        trace_to_file("ERROR: Next block is busy, can't merge");
        return;
    }

    p_block->sz_size += p_next_block->sz_size + CANARY_SIZE;
    remove_block(p_next_block);
    update_block_canary(p_block);
}

// Find the first block that is big enough to fit the requested size, otherwise return NULL
block_metadata_t *find_fitting_block(size_t sz_size) {
    trace_to_file("> Looking for a free block of at least %zu B", sz_size);
    block_metadata_t *p_current = p_meta_pool;

    while (p_current != NULL) {
        if (!p_current->b_is_busy && p_current->sz_size >= sz_size) {
            trace_to_file("> Found a free block!");
            return p_current;
        }
        p_current = p_current->p_next;
    }

    trace_to_file("No free block found");
    return NULL;
}

// Log to STDERR
bool my_log(const char *s_fmt, ...) {
    va_list args;

    va_start(args, s_fmt);
    bool b_ret = my_vlog(STDERR_FILENO, s_fmt, args);
    va_end(args);

    return b_ret;
}

// Log to STDERR and to the trace file
bool my_log_trace(const char *s_fmt, ...) {
    va_list args;

    va_start(args, s_fmt);
    bool b_ret = my_vlog(STDERR_FILENO, s_fmt, args);
    va_end(args);

    va_start(args, s_fmt);
    b_ret &= my_vlog_to_file(s_fmt, args);
    va_end(args);

    return b_ret;
}

// Log to the file given by the environment variable MSM_OUTPUT if it is set,
// otherwise do nothing and return false. This version takes a variable number of arguments.
bool my_log_to_file(const char *s_fmt, ...) {
    va_list args;

    va_start(args, s_fmt);
    bool b_ret = my_vlog_to_file(s_fmt, args);
    va_end(args);

    return b_ret;
}

// Log to the given file descriptor, with a variable argument list
bool my_vlog(const int i_fd, const char *s_fmt, va_list args) {
    va_list args_copy;
    va_copy(args_copy, args); // Keep a copy of the args for the second call to vsnprintf
    char *s_buf  = NULL;
    int i_length = 0;

    i_length = vsnprintf(s_buf, i_length, s_fmt, args);

    if (i_length < 0) {
        // There was a problem with vsnprintf
        return false;
    }

    s_buf    = alloca(i_length + 1);
    i_length = vsnprintf(s_buf, i_length + 1, s_fmt, args_copy);

    if (write(i_fd, s_buf, i_length) >= 0) {
        return true;
    }

    return false;
}

// Log to the file given by the environment variable MSM_OUTPUT if it is set,
// otherwise do nothing and return false. This version takes a va_list.
bool my_vlog_to_file(const char *s_fmt, va_list args) {
    static int i_log_fd = -1; // -1 means uninitialized, 0 means false, otherwise true
    if (i_log_fd == -1) {
        // Cache the result of the getenv call
        debug_print("Checking for environment variable MSM_OUTPUT");
        char *s_log_env = getenv("MSM_OUTPUT"); // MSM_OUPUT

        if (s_log_env == NULL) {
            i_log_fd = 0;
            debug_print("MSM_OUTPUT is NULL, not logging");
        }
        else {
            // Open the file for writing, creating it if it doesn't exist, and truncating otherwise
            i_log_fd = creat(s_log_env, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH); // 0644

            if (i_log_fd < 0) {
                // Can't use strerror here because it uses malloc
                my_log("ERROR: Could not open file %s for writing: ERRNO=%d\n", s_log_env, errno);
                _exit(EXIT_FAILURE);
            }
            debug_print("Logging to file: %s", s_log_env);
        }
    }

    if (i_log_fd > 0) {
        return my_vlog(i_log_fd, s_fmt, args);
    }

    return false;
}

// Print the contents of a block to the trace file
void print_block(block_metadata_t *p_block) {
    trace_to_file("Block number:  %ld", p_block - p_meta_pool);
    trace_to_file("Block address: %p", p_block);
    trace_to_file("Data offset:   %zu", p_block->p_data_offset);
    trace_to_file("Data string:   '%s'", (char *)get_block_data_ptr(p_block));
    trace_to_file("Is block busy? %s", p_block->b_is_busy ? "Yes" : "No");
    trace_to_file("Block size:    %zu B", p_block->sz_size);
    trace_to_file("Block canary:  %016lx", p_block->ui64_canary);
    trace_to_file("Prev block:    %p", p_block->p_prev);
    if (p_block->p_prev != NULL) {
        trace_to_file("Prev block n.: %ld", p_block->p_prev - p_meta_pool);
    }
    trace_to_file("Next block:    %p", p_block->p_next);
    if (p_block->p_next != NULL) {
        trace_to_file("Next block n.: %ld", p_block->p_next - p_meta_pool);
    }
}

// Print the contents of all allocated blocks in the metadata pool to the trace file
void print_block_list() {
    trace_to_file("================");
    trace_to_file("Blocks in metadata list:");
    block_metadata_t *p_current = p_meta_pool;
    while (p_current != NULL) {
        trace_to_file("----------------");
        print_block(p_current);
        p_current = p_current->p_next;
    }
    trace_to_file("================");
}

// Print the contents of all blocks in the metadata pool to the trace file, even if unallocated
void print_all_blocks() {
    trace_to_file("================");
    trace_to_file("All blocks in metadata pool:");
    block_metadata_t *p_current     = p_meta_pool;
    block_metadata_t *sz_meta_limit = p_meta_pool + sz_meta_pool_count;

    while (p_current < sz_meta_limit && p_current->sz_size > 0) {
        trace_to_file("----------------");
        print_block(p_current);
        p_current++;
    }
    trace_to_file("================");
}

void *check_canary_worker() {
    block_metadata_t *p_block;

    while (true) {
        usleep(100000); // 100 ms delay between checks

        p_block = p_meta_pool;
        debug_print("Checking canaries...\n");

        while (p_block != NULL) {
            if (p_block->b_is_busy && !check_canary(p_block)) {
                my_log_trace("ERROR: Heap overflow (corrupted canary) [Thread worker]\n");
                _exit(EXIT_BAD_CANARY);
            }

            p_block = p_block->p_next;
        }
    }
}

void *my_malloc(size_t size) {
    trace_to_file("* Calling my_malloc with %zu B", size);

    if (size == 0) {
        return NULL; // Can't allocate 0 bytes
    }

    // Initialize the pools if needed
    if (!check_init_pools()) {
        errno = ENOMEM;
        return NULL;
    }

    block_metadata_t *p_fitting_block = find_fitting_block(size);
    if (p_fitting_block != NULL) {
        // Found a free block that fits the requested size
        resize_block(p_fitting_block, size);

        return get_block_data_ptr(p_fitting_block);
    }

    // No fitting free block found, so we need to allocate a new block

    block_metadata_t *p_last = get_last_block();

    block_metadata_t *p_new_block = allocate_after(p_last, size, true);

    if (p_new_block == NULL) {
        my_log_trace("ERROR: Failed allocating new block\n");
        errno = ENOMEM;
        return NULL;
    }

    p_new_block->b_is_busy = true;
    // update_block_canary(p_new_block);

    void *p_data_ptr = get_block_data_ptr(p_new_block);

    trace_to_file("* Allocated %zu B at %p", size, p_data_ptr);
    return p_data_ptr;
}

void my_free(void *ptr) {
    trace_to_file("* Calling my_free for %p", ptr);

    if (ptr == NULL) {
        trace_to_file("ptr is NULL, doing nothing");
        return;
    }

    block_metadata_t *p_block = find_busy_block_from_ptr(ptr);

    trace_to_file("Found the block to free at %p", p_block);

    p_block->b_is_busy = false;

    block_metadata_t *p_next_block = p_block->p_next;
    block_metadata_t *p_prev_block = p_block->p_prev;

    // Expand block size to the full size of the data block
    if (p_next_block != NULL) {
        size_t sz_new_size = p_next_block->p_data_offset - p_block->p_data_offset - CANARY_SIZE;
        if (sz_new_size > p_block->sz_size) {
            trace_to_file(
                "Expanding block size from %zu B to %zu B", p_block->sz_size, sz_new_size);
            p_block->sz_size = sz_new_size;
        }
    }

    // Merge with next block if possible
    if (p_next_block != NULL && !p_next_block->b_is_busy) {
        trace_to_file("Merging with next block");
        merge_block(p_block);
    }

    // Merge with previous block if possible
    if (p_prev_block != NULL && !p_prev_block->b_is_busy) {
        trace_to_file("Merging with previous block");
        merge_block(p_prev_block);
    }

    trace_to_file("* Freed block at %p", p_block);
}

void *my_calloc(size_t nmemb, size_t size) {
    trace_to_file("* Calling my_calloc with %zu items of %zu B", nmemb, size);

    size_t sz_total_size = nmemb * size;

    // Use malloc to allocate memory
    void *p_data_ptr = my_malloc(sz_total_size);

    if (p_data_ptr == NULL) {
        // If malloc failed, return NULL
        return NULL;
    }

    // If malloc succeeded, set the allocated memory to 0
    memset(p_data_ptr, 0, sz_total_size);

    return p_data_ptr;
}

void *my_realloc(void *ptr, size_t size) {
    trace_to_file("* Calling my_realloc for %p with %zu B", ptr, size);

    if (ptr == NULL) {
        // If ptr is NULL, realloc is equivalent to malloc
        return my_malloc(size);
    }

    if (size == 0) {
        // If size is 0, realloc is equivalent to free
        my_free(ptr);
        return NULL;
    }

    block_metadata_t *p_block = find_busy_block_from_ptr(ptr);

    size_t sz_old_size = p_block->sz_size;

    if (size == sz_old_size) {
        // If the new size is the same as the current size, do nothing
        trace_to_file("* Block at %p is the same size, returning it as-is", ptr);
        return ptr;
    }

    if (size < sz_old_size) {
        // If the new size is smaller than the current size, shrink the block
        trace_to_file("* Block at %p is bigger, shrinking it", ptr);
        resize_block(p_block, size);
        return ptr;
    }

    // If the new size is larger than the current size, allocate a new block, copy the data and free
    // the old block
    void *p_new_ptr = my_malloc(size);
    memcpy(p_new_ptr, ptr, sz_old_size);
    my_free(ptr);

    trace_to_file(
        "* Reallocated from %zu B at %p to %zu B at %p", sz_old_size, ptr, size, p_new_ptr);
    return p_new_ptr;
}

#ifdef DYNAMIC
/*
 * Lorsque la bibliothèque sera compilée en .so les symboles malloc/free/calloc/realloc seront
 * visibles
 */

void *malloc(size_t size) { return my_malloc(size); }

void free(void *ptr) { my_free(ptr); }

void *calloc(size_t nmemb, size_t size) { return my_calloc(nmemb, size); }

void *realloc(void *ptr, size_t size) { return my_realloc(ptr, size); }

#endif
