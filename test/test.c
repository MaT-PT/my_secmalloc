#define _GNU_SOURCE
#include <criterion/criterion.h>
#include <criterion/redirect.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include "my_secmalloc.h"
#include "my_secmalloc_private.h"

void redir_stderr() { cr_redirect_stderr(); }

TestSuite(my_log_redirect, .init = redir_stderr);
TestSuite(my_free_redirect, .init = redir_stderr);

Test(mmap, simple) {
    // Question: Est-ce que printf fait un malloc ?
    printf("Ici on fait un test simple de mmap\n");
    void *ptr = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
    cr_expect(ptr != NULL);
    int res = munmap(ptr, 4096);
    cr_expect(res == 0);
    char *str = my_malloc(15);
    strncpy(str, "ca marche", 15);
    printf("bla %s\n", str);
}

Test(my_log_redirect, no_args) {
    my_log("Hello world!\n");
    cr_expect_stderr_eq_str("Hello world!\n");
}

Test(my_log_redirect, args_short) {
    my_log("Int: %d\nString: %s\nPointer: %p\n", 2600, "Hello world!", (void *)0xdeadbeef);
    cr_expect_stderr_eq_str("Int: 2600\nString: Hello world!\nPointer: 0xdeadbeef\n");
}

Test(my_log_redirect, args_very_long) {
    char buf[513];
    for (size_t i = 0; i < sizeof(buf) - 1; i += 4) {
        buf[i + 0] = '2';
        buf[i + 1] = '6';
        buf[i + 2] = '0';
        buf[i + 3] = '0';
    }
    buf[sizeof(buf) - 1] = '\0';

    my_log("Test: %s!\n", buf);
    cr_expect_stderr_eq_str(
        "Test: "
        "2600260026002600260026002600260026002600260026002600260026002600260026002600260026002600"
        "2600260026002600260026002600260026002600260026002600260026002600260026002600260026002600"
        "2600260026002600260026002600260026002600260026002600260026002600260026002600260026002600"
        "2600260026002600260026002600260026002600260026002600260026002600260026002600260026002600"
        "2600260026002600260026002600260026002600260026002600260026002600260026002600260026002600"
        "260026002600260026002600260026002600260026002600260026002600260026002600!\n");
}

Test(my_malloc, empty_malloc) {
    char *ptr = my_malloc(0);
    cr_expect_null(ptr);
}

Test(my_malloc, simple) {
    char *ptr1 = my_malloc(5);
    cr_assert_not_null(ptr1);
    strncpy(ptr1, "Abc", 5);
    cr_expect_str_eq(ptr1, "Abc");

    char *ptr2 = my_malloc(20);
    cr_assert_not_null(ptr2);
    strncpy(ptr2, "Test abc 1", 20);
    cr_expect_str_eq(ptr2, "Test abc 1");

    my_free(ptr1);
    my_free(ptr2);

    char *ptr3 = my_malloc(8);
    cr_assert_not_null(ptr3);
    strncpy(ptr3, "ABC3", 8);
    cr_expect_str_eq(ptr3, "ABC3");

    // print_block_list();
    // print_all_blocks();
}

Test(my_malloc, canary_unique) {
    srand(2600);
    uint64_t canary, canary_old = 0;

    for (int i = 0; i < 100; ++i) {
        canary = get_random_canary();
        // printf("canary: %016lx\n", canary);
        cr_expect_neq(canary, 0);
        cr_expect_neq(canary, canary_old);
        canary_old = canary;
    }
}

Test(my_malloc, canary_present) {
    srand(2600);

    char *ptr = my_malloc(15);
    cr_assert_not_null(ptr);

    block_metadata_t *p_block = find_block_from_ptr(ptr);

    uint64_t canary = *((uint64_t *)(ptr + 15));

    cr_expect_eq(canary, p_block->ui64_canary);
    cr_expect_neq(p_block->ui64_canary, 0);
}

Test(my_malloc, expand_meta) {
    srand(2600);

    char *ptr; //, *old_ptr = NULL;
    for (int i = 0; i < 257; ++i) {
        // printf("i: %d\n", i);
        ptr = my_malloc(16);
        cr_assert_not_null(ptr);
        // printf("ptr: %p\n", ptr);
        // if (old_ptr) {
        //     cr_expect_eq(ptr, old_ptr + 16 + CANARY_SIZE);
        // }
        // old_ptr = ptr;
    }
}

Test(my_malloc, expand_data) {
    srand(2600);

    char *ptr = NULL;
    for (int i = 0; i < 160; ++i) {
        ptr = my_malloc(PAGE_SIZE / 2);
        cr_assert_not_null(ptr);
        // printf("ptr: %p\n", ptr);
    }
}

Test(my_malloc, shrink1) {
    srand(2600);

    char *ptr1 = my_malloc(64);
    char *ptr2 = my_malloc(64);
    cr_assert_not_null(ptr1);
    cr_assert_not_null(ptr2);

    block_metadata_t *p_block1 = find_block_from_ptr(ptr1);
    cr_expect_eq(p_block1->sz_size, 64);

    for (int i = 63; i > 0; i -= 10) {
        // print_all_blocks();
        my_free(ptr1);
        // print_all_blocks();
        cr_expect_eq(p_block1->sz_size, 64);
        ptr1 = my_malloc(i);
        cr_assert_not_null(ptr1);
        // my_log("i: %lu, p_block1->sz_size: %lu\n", i, p_block1->sz_size);
        cr_expect_eq(p_block1->sz_size, (unsigned)i);
    }

    // print_all_blocks();

    my_free(ptr1);
    my_free(ptr2);
}

Test(my_malloc, shrink2) {
    srand(2600);

    char *ptr1 = my_malloc(64);
    char *ptr2 = my_malloc(64);
    cr_assert_not_null(ptr1);
    cr_assert_not_null(ptr2);

    block_metadata_t *p_block1 = find_block_from_ptr(ptr1);

    for (int i = 63; i > 0; i -= 1) {
        // print_all_blocks();
        my_free(ptr1);
        // print_all_blocks();
        cr_expect_eq(p_block1->sz_size, 64);
        ptr1 = my_malloc(i);
        cr_assert_not_null(ptr1);
        cr_expect_eq(p_block1->sz_size, (unsigned)i);
    }

    // print_all_blocks();

    my_free(ptr1);
    my_free(ptr2);
}

Test(my_malloc, shrink3) {
    srand(2600);

    char *ptr1 = my_malloc(64);
    char *ptr2 = my_malloc(64);
    cr_assert_not_null(ptr1);
    cr_assert_not_null(ptr2);

    // print_all_blocks();

    block_metadata_t *p_block1 = find_block_from_ptr(ptr1);
    cr_expect_eq(p_block1->sz_size, 64);

    my_free(ptr1);
    ptr1 = my_malloc(60);
    // print_all_blocks();

    cr_expect_eq(p_block1->sz_size, 60);

    my_free(ptr2);
    my_free(ptr1);
    // print_all_blocks();
    cr_expect_eq(p_block1->sz_size, 2 * 64 + CANARY_SIZE);
}

Test(my_free, null_check) {
    // free(NULL) must not crash
    my_free(NULL);
}

Test(my_free, simple) {
    srand(2600);

    char *ptr1 = my_malloc(16);
    cr_assert_not_null(ptr1);
    block_metadata_t *p_block1 = find_block_from_ptr(ptr1);
    cr_expect(p_block1->b_is_busy);

    char *ptr2 = my_malloc(16);
    cr_assert_not_null(ptr2);
    block_metadata_t *p_block2 = find_block_from_ptr(ptr2);
    cr_expect(p_block2->b_is_busy);

    cr_expect_neq(ptr1, ptr2);

    my_free(ptr1);
    cr_expect_not(p_block1->b_is_busy);

    char *ptr3 = my_malloc(16);
    cr_assert_not_null(ptr3);
    block_metadata_t *p_block3 = find_block_from_ptr(ptr3);
    cr_expect(p_block3->b_is_busy);

    cr_expect_eq(ptr1, ptr3);

    my_free(ptr2);
    cr_expect_not(p_block2->b_is_busy);

    my_free(ptr3);
    cr_expect_not(p_block3->b_is_busy);

    char *ptr4 = my_malloc(17);
    cr_assert_not_null(ptr4);
    block_metadata_t *p_block4 = find_block_from_ptr(ptr4);
    cr_expect(p_block4->b_is_busy);

    cr_expect_neq(ptr2, ptr4);

    my_free(ptr4);
    cr_expect_not(p_block4->b_is_busy);

    char *ptr5 = my_malloc(10);
    cr_assert_not_null(ptr5);
    block_metadata_t *p_block5 = find_block_from_ptr(ptr5);
    cr_expect(p_block5->b_is_busy);

    cr_expect_eq(ptr1, ptr5);

    my_free(ptr5);
    cr_expect_not(p_block5->b_is_busy);

    // print_all_blocks();
}

Test(my_free, merge) {
    srand(2600);

    char *ptr1 = my_malloc(16);
    char *ptr2 = my_malloc(16);
    char *ptr3 = my_malloc(16);
    cr_assert_not_null(ptr1);
    cr_assert_not_null(ptr2);
    cr_assert_not_null(ptr3);
    cr_expect_neq(ptr1, ptr2);
    cr_expect_neq(ptr1, ptr3);
    cr_expect_neq(ptr2, ptr3);

    strncpy(ptr1, "ABCDEFGHIJKLM12", 16);
    strncpy(ptr2, "abcdefghijklmno", 16);
    strncpy(ptr3, "NOPQRSTUVWXYZ45", 16);
    cr_expect_str_eq(ptr1, "ABCDEFGHIJKLM12");
    cr_expect_str_eq(ptr2, "abcdefghijklmno");
    cr_expect_str_eq(ptr3, "NOPQRSTUVWXYZ45");

    my_free(ptr1);
    my_free(ptr3);
    // print_all_blocks();

    block_metadata_t *p_block1 = find_block_from_ptr(ptr1);
    block_metadata_t *p_block2 = find_block_from_ptr(ptr2);
    block_metadata_t *p_block3 = find_block_from_ptr(ptr3);

    cr_expect_eq(p_block1->sz_size, 16);
    cr_expect_eq(p_block2->sz_size, 16);
    cr_expect_eq(p_block3->sz_size, 16);

    my_free(ptr2);
    // print_all_blocks();

    cr_redirect_stderr();
    p_block1 = find_block_from_ptr(ptr1);
    p_block2 = find_block_from_ptr(ptr2);
    p_block3 = find_block_from_ptr(ptr3);

    cr_expect_eq(p_block1->sz_size, 64);
    cr_expect_null(p_block2);
    cr_expect_null(p_block3);
}

Test(my_free, not_init, .exit_code = EXIT_INVALID_PTR) {
    // Try freeing a random pointer
    my_free((void *)0x1234567890abcdef);
}

Test(my_free, double_free, .exit_code = EXIT_DOUBLE_FREE) {
    srand(2600);

    char *ptr1 = my_malloc(16);
    cr_assert_not_null(ptr1);

    my_free(ptr1);
    my_free(ptr1);
}

Test(my_free, corrupted_canary, .exit_code = EXIT_BAD_CANARY) {
    srand(2600);

    char *ptr1 = my_malloc(16);
    cr_assert_not_null(ptr1);

    strncpy(ptr1, "Test abcdefghijkl", 18);
    my_free(ptr1);
}

Test(my_free, invalid_ptr, .exit_code = EXIT_INVALID_PTR) {
    srand(2600);

    char *ptr1 = my_malloc(16);
    cr_assert_not_null(ptr1);

    ptr1++;

    my_free(ptr1);
}

Test(my_calloc, zero_check) {
    // calloc must initialize the memory to 0
    char *str = my_calloc(15, sizeof(char));
    cr_assert_not_null(str);
    cr_expect_arr_eq(str, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 15);
}

Test(my_calloc, empty_calloc) {
    char *str = my_calloc(0, sizeof(char));
    cr_assert_null(str);

    str = my_calloc(0, sizeof(int));
    cr_assert_null(str);

    str = my_calloc(16, 0);
    cr_assert_null(str);
}

Test(my_calloc, size) {
    srand(2600);

    // calloc(n, size) must be equivalent to malloc(n * size)
    char *ptr1 = my_calloc(2600, 42);
    cr_assert_not_null(ptr1);
    block_metadata_t *p_block1 = find_block_from_ptr(ptr1);
    cr_expect_eq(p_block1->sz_size, 2600 * 42);

    my_free(ptr1);
}

Test(my_realloc, null_check) {
    srand(2600);

    // realloc(NULL, size) must be equivalent to malloc(size)
    char *ptr1 = my_realloc(NULL, 42);
    cr_assert_not_null(ptr1);
    block_metadata_t *p_block1 = find_block_from_ptr(ptr1);
    cr_expect_eq(p_block1->sz_size, 42);

    my_free(ptr1);
}

Test(my_realloc, zero_size) {
    srand(2600);

    char *ptr1 = my_malloc(16);
    cr_assert_not_null(ptr1);

    block_metadata_t *p_block1 = find_block_from_ptr(ptr1);
    cr_expect(p_block1->b_is_busy);

    // realloc(ptr, 0) must be equivalent to free(ptr)
    char *ptr2 = my_realloc(ptr1, 0);
    cr_assert_null(ptr2);
    cr_expect_not(p_block1->b_is_busy);
}

Test(my_realloc, smaller) {
    srand(2600);

    char *ptr1 = my_malloc(32);
    cr_assert_not_null(ptr1);
    block_metadata_t *p_block1 = find_block_from_ptr(ptr1);
    cr_expect(p_block1->b_is_busy);

    strncpy(ptr1, "Test abc", 32);
    cr_expect_str_eq(ptr1, "Test abc");

    char *ptr2 = my_realloc(ptr1, 16);
    cr_assert_not_null(ptr2);
    block_metadata_t *p_block2 = find_block_from_ptr(ptr2);
    cr_expect(p_block2->b_is_busy);
    cr_expect_eq(ptr1, ptr2);

    cr_expect_str_eq(ptr2, "Test abc");

    my_free(ptr2);
}

Test(my_realloc, bigger) {
    srand(2600);

    char *ptr1 = my_malloc(16);
    cr_assert_not_null(ptr1);
    block_metadata_t *p_block1 = find_block_from_ptr(ptr1);
    cr_expect(p_block1->b_is_busy);

    strncpy(ptr1, "Test abc", 16);
    cr_expect_str_eq(ptr1, "Test abc");

    char *ptr2 = my_realloc(ptr1, 32);
    cr_assert_not_null(ptr2);
    block_metadata_t *p_block2 = find_block_from_ptr(ptr2);
    cr_expect(p_block2->b_is_busy);
    cr_expect_not(p_block1->b_is_busy);
    cr_expect_neq(ptr1, ptr2);

    cr_expect_str_eq(ptr2, "Test abc");

    my_free(ptr2);
}

Test(my_realloc, not_init, .exit_code = EXIT_INVALID_PTR) {
    // Try reallocating a random pointer
    my_realloc((void *)0x1234567890abcdef, 2600);
}

Test(my_realloc, double_free, .exit_code = EXIT_DOUBLE_FREE) {
    srand(2600);

    char *ptr1 = my_malloc(16);
    cr_assert_not_null(ptr1);

    my_free(ptr1);
    my_realloc(ptr1, 2600);
}

Test(my_realloc, corrupted_canary, .exit_code = EXIT_BAD_CANARY) {
    srand(2600);

    char *ptr1 = my_malloc(16);
    cr_assert_not_null(ptr1);

    strncpy(ptr1, "Test abcdefghijkl", 18);
    my_realloc(ptr1, 2600);
}

Test(my_realloc, invalid_ptr, .exit_code = EXIT_INVALID_PTR) {
    srand(2600);

    char *ptr1 = my_malloc(16);
    cr_assert_not_null(ptr1);

    ptr1++;

    my_realloc(ptr1, 2600);
}

Test(thread_worker, corrupted_canary, .exit_code = EXIT_BAD_CANARY) {
    srand(2600);

    char *ptr1 = my_malloc(16);
    cr_assert_not_null(ptr1);

    strncpy(ptr1, "Test abcdefghijkl", 18);

    // Wait for the thread to notice the corrupted canary
    sleep(3);
}
