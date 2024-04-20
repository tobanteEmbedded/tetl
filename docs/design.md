# Design

## Issues

### Forced to use namesapce std

- `std::construct_at`
  - Only way to get constexpr "placement new"
- tuple protocol (structured bindings)
  - `std::tuple_size`
  - `std::tuple_element`
- three-way comparison
  - `operator<=>` returns a type from `std` for builtin types
