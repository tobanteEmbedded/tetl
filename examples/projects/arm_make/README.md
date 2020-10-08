# Example ARM Makefile Project

```sh
# Automatically selects toolchain from path, using which & a little regex magic. See make/ folder.
make all            # Build & Link with -Os
make DEBUG=1 all    # Build & Link with -Og -g3 -gdb
make CLANG=1 all    # Build & Link with clang, selected from $PATH
make clean          # Delete build dir & object files
make toolchain      # Print toolchain root & version

# Manual set toolchain path
export PATH=$HOME/bin/gcc-arm-none-eabi-9-2020-q2-update/bin:$PATH
make toolchain
make all
```
