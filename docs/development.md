# Development

## CMake Presets

```sh
# Todo: How does "Ninja Multi-Config" work in VSCode when presets are enabled?
cmake --list-presets=all .
cmake --preset desktop
cmake --build --preset desktop
ctest --preset desktop
```
