# Building

## Build on Desktop

```sh
cd $PROJECT_ROOT
mkdir build && cd build
cmake ..
cmake --build  .
ctest
```

### Coverage

Needs `gcov` & `lcov` installed:

```sh
make coverage report
firefox build_coverage/lcov/index.html
```

### Documentation

You can build the documentation with `doxygen`:

```sh
cd $PROJECTROOT/docs
doxygen Doxyfile.in
firefox doc-build/html/index.html
```
