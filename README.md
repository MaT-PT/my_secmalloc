# my_secmalloc

Secure malloc implementation (school project from 2023)

## Features

- Allocated data separated from block metadata, preventing abuse of heap overflows
- Canary protection against overflows before running any operation on a block
- Checks for double-free conditions
- Spawns a thread that checks for canary integrity every 100 ms
- Checks for memory leaks (non-freed blocks at program exit)
- "Smart" block splitting/coalescing, preventing memory fragmentation as much as possible
- Optional verbose logging to a file of every action taken by the lib

## Building

Compile with `make`.

Possible targets:

- `make all`: build `libmy_secmalloc.so` without verbose debugging to STDERR
- `make dynamic`: build `libmy_secmalloc.so` without verbose debugging, exporting malloc-related functions for drop-in replacement of libc's functions
- `make dyn_debug`: like `make dynamic` with verbose debug messages sent to STDERR
- `make static`: build `libmy_secmalloc.a` for testing purposes
- `make build_test`: build test program (`test/test`)
- `make test`: build and run test program
- `make clean`: delete intermediate compilation files

## Usage

### Running programs with libmy_secmalloc.o

To run a program using this lib's functions instead of libc's, build it with `make dynamic` (or `make dyn_debug`) and load the .so with `LD_PRELOAD`.

You can also set the environment variable `MSM_OUTPUT` to log everything to a file (allocations, function calls, etc.).

```bash
LD_PRELOAD=./lib/libmy_secmalloc.so <program> [arguments...]

# For example:
LD_PRELOAD=./lib/libmy_secmalloc.so ls -lA

MSM_OUTPUT=malloc-ls.log LD_PRELOAD=./lib/libmy_secmalloc.so ls -lA
```

### Testing

Build the test program with `make static build_test` (or run it directly with `make static test`).
