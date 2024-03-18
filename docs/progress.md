# Progress

## Standard

Unless stated otherwise, all papers are implemented to work with the minimum C++ standard (currently C++20).

### C++26

|                                       Paper                                        |                                   Name                                   |  Status  | Comment |
| :--------------------------------------------------------------------------------: | :----------------------------------------------------------------------: | :------: | :-----: |
|  [P0543R3](https://www.open-std.org/jtc1/sc22/wg21/docs/papers/2023/p0543r3.html)  |                          Saturation Arithmetic                           |  _WIP_   |         |
| [P0792R14](https://www.open-std.org/jtc1/sc22/wg21/docs/papers/2023/p0792r14.html) |           `std::function_ref`: type-erased callable reference            |  _WIP_   |         |
|  [P0952R1](https://www.open-std.org/jtc1/sc22/wg21/docs/papers/2023/p0952r1.html)  |            A new specification for `std::generate_canonical`             |          |         |
|  [P1383R2](https://www.open-std.org/jtc1/sc22/wg21/docs/papers/2023/p1383r2.pdf)   |               More constexpr for `<cmath>` and `<complex>`               | **Done** |         |
| [P1673R13](https://www.open-std.org/jtc1/sc22/wg21/docs/papers/2023/p1673r13.html) |  `<linalg>`: A free function linear algebra interface based on the BLAS  |  _WIP_   |         |
|  [P2013R5](https://www.open-std.org/jtc1/sc22/wg21/docs/papers/2023/p2013r5.html)  |             Freestanding Language: Optional `::operator new`             |          |         |
|  [P2264R7](https://www.open-std.org/jtc1/sc22/wg21/docs/papers/2023/p2264r7.html)  |            Make `assert()` macro user friendly for C and C++             |          |         |
|  [P2497R0](https://www.open-std.org/jtc1/sc22/wg21/docs/papers/2023/p2497r0.html)  |         Testing for success or failure of `<charconv>` functions         | **Done** |         |
|  [P2538R1](https://www.open-std.org/jtc1/sc22/wg21/docs/papers/2022/p2538r1.html)  |                        ADL-proof `std::projected`                        |          |         |
|  [P2546R5](https://www.open-std.org/jtc1/sc22/wg21/docs/papers/2023/p2546r5.html)  |                     `<debugging>`: Debugging Support                     |          |         |
|  [P2562R1](https://www.open-std.org/jtc1/sc22/wg21/docs/papers/2022/p2562r1.pdf)   |                         constexpr stable sorting                         | **Done** |         |
|  [P2592R3](https://www.open-std.org/jtc1/sc22/wg21/docs/papers/2023/p2592r3.html)  |             Hashing support for `std::chrono` value classes              |          |         |
|  [P2630R4](https://www.open-std.org/jtc1/sc22/wg21/docs/papers/2023/p2630r4.html)  |                            `std::submdspan()`                            |  _WIP_   |         |
|  [P2637R3](https://www.open-std.org/jtc1/sc22/wg21/docs/papers/2023/p2637r3.html)  |                               Member visit                               |          |         |
|  [P2641R4](https://www.open-std.org/jtc1/sc22/wg21/docs/papers/2023/p2641r4.html)  |                        `std::is_within_lifetime`                         |          |         |
|  [P2697R1](https://www.open-std.org/jtc1/sc22/wg21/docs/papers/2023/p2697r1.pdf)   |                 Interfacing `bitset` with `string_view`                  | **Done** |         |
|  [P2714R1](https://www.open-std.org/jtc1/sc22/wg21/docs/papers/2023/p2714r1.html)  | `std::bind_front`, `std::bind_back`, and `std::not_fn` to NTTP callables |          |         |
|  [P2819R2](https://www.open-std.org/jtc1/sc22/wg21/docs/papers/2023/p2819r2.pdf)   |                  Added tuple protocol to `std::complex`                  | **Done** |         |
|  [P2821R5](https://www.open-std.org/jtc1/sc22/wg21/docs/papers/2023/p2821r5.html)  |                            `std::span::at()`                             |          |         |
|  [P2937R0](https://www.open-std.org/jtc1/sc22/wg21/docs/papers/2023/p2937r0.html)  |                   Freestanding: removing `std::strtok`                   |          |         |

### C++23

|                                       Paper                                        |                                           Name                                           |  Status  | Comment |
| :--------------------------------------------------------------------------------: | :--------------------------------------------------------------------------------------: | :------: | :-----: |
| [P0323R12](https://www.open-std.org/jtc1/sc22/wg21/docs/papers/2022/p0323r12.html) |                                       `<expected>`                                       |  _WIP_   |         |
|  [P0429R9](https://www.open-std.org/jtc1/sc22/wg21/docs/papers/2022/p0429r9.pdf)   |                                       `<flat_map>`                                       |          |         |
|  [P0533R9](https://www.open-std.org/jtc1/sc22/wg21/docs/papers/2021/p0533r9.pdf)   |                         constexpr for `<cmath>` and `<cstdlib>`                          | **Done** |         |
|  [P0627R6](https://www.open-std.org/jtc1/sc22/wg21/docs/papers/2021/p0627r6.pdf)   |                                   `std::unreachable()`                                   | **Done** |         |
|  [P0798R8](https://www.open-std.org/jtc1/sc22/wg21/docs/papers/2021/p0798r8.html)  |                          Monadic operations for `std::optional`                          |  _WIP_   |         |
|  [P1048R1](https://www.open-std.org/jtc1/sc22/wg21/docs/papers/2020/p1048r1.pdf)   |                                  `std::is_scoped_enum`                                   | **Done** |         |
| [P1072R10](https://www.open-std.org/jtc1/sc22/wg21/docs/papers/2021/p1072r10.html) |                       `std::basic_string::resize_and_overwrite()`                        |          |         |
|  [P1222R4](https://www.open-std.org/jtc1/sc22/wg21/docs/papers/2022/p1222r4.pdf)   |                                       `<flat_set>`                                       |  _WIP_   |         |
|  [P1272R4](https://www.open-std.org/jtc1/sc22/wg21/docs/papers/2021/p1272r4.html)  |                                    `std::byteswap()`                                     | **Done** |         |
|  [P1679R3](https://www.open-std.org/jtc1/sc22/wg21/docs/papers/2020/p1679r3.html)  |         `std::basic_string::contains()` and `std::basic_string_view::contains()`         | **Done** |         |
|  [P1682R3](https://www.open-std.org/jtc1/sc22/wg21/docs/papers/2021/p1682r3.html)  |                                   `std::to_underlying`                                   | **Done** |         |
|  [P1951R1](https://www.open-std.org/jtc1/sc22/wg21/docs/papers/2021/p1951r1.html)  |           Default template arguments for `std::pair`'s forwarding constructor            | **Done** |         |
|  [P1989R2](https://www.open-std.org/jtc1/sc22/wg21/docs/papers/2021/p1989r2.pdf)   |                      Range constructor for `std::basic_string_view`                      |          |         |
|  [P2136R3](https://www.open-std.org/jtc1/sc22/wg21/docs/papers/2021/p2136r3.html)  |                                    `std::invoke_r()`                                     | **Done** |         |
|  [P2162R2](https://www.open-std.org/jtc1/sc22/wg21/docs/papers/2021/p2162r2.html)  |               DR17: `std::visit()` for classes derived from `std::variant`               |          |         |
|  [P2166R1](https://www.open-std.org/jtc1/sc22/wg21/docs/papers/2020/p2166r1.html)  | Prohibiting `std::basic_string` and `std::basic_string_view` construction from `nullptr` | **Done** |         |
|  [P2231R1](https://www.open-std.org/jtc1/sc22/wg21/docs/papers/2021/p2231r1.html)  |                  DR20: constexpr for `std::optional` and `std::variant`                  |          |         |
|  [P2251R1](https://www.open-std.org/jtc1/sc22/wg21/docs/papers/2021/p2251r1.pdf)   |         Require `std::span` & `std::basic_string_view` to be _TriviallyCopyable_         | **Done** |         |
|  [P2291R3](https://www.open-std.org/jtc1/sc22/wg21/docs/papers/2021/p2291r3.pdf)   |      constexpr for integral overloads of `std::to_chars()` and `std::from_chars()`.      | **Done** |         |
|  [P2401R0](https://www.open-std.org/jtc1/sc22/wg21/docs/papers/2021/p2401r0.html)  |               Add a conditional noexcept specification to `std::exchange`                | **Done** |         |
|  [P2417R2](https://www.open-std.org/jtc1/sc22/wg21/docs/papers/2022/p2417r2.pdf)   |                                 constexpr `std::bitset`                                  | **Done** |         |
|  [P2445R1](https://www.open-std.org/jtc1/sc22/wg21/docs/papers/2022/p2445r1.pdf)   |                                  `std::forward_like()`                                   | **Done** |         |
|  [P2505R5](https://www.open-std.org/jtc1/sc22/wg21/docs/papers/2022/p2505r5.html)  |                          Monadic operations for `std::expected`                          |  _WIP_   |         |
|  [P2517R1](https://www.open-std.org/jtc1/sc22/wg21/docs/papers/2022/p2517r1.html)  |                 Add a conditional noexcept specification to `std::apply`                 |          |         |
|  [P2549R1](https://www.open-std.org/jtc1/sc22/wg21/docs/papers/2022/p2549r1.html)  |              `std::unexpected<E>` should have `error()` as member accessor               | **Done** |         |

### C++20

|  Paper  |                                        Name                                        |  Status  | Comment |
| :-----: | :--------------------------------------------------------------------------------: | :------: | :-----: |
| P0463R1 |                                   `std::endian`                                    | **Done** |         |
| P0202R3 |                    constexpr for `<algorithm>` and `<utility>`                     | **Done** |         |
| P0415R1 |                           More constexpr for `<complex>`                           | **Done** |         |
| P0457R2 |     String prefix and suffix checking: string(\_view) ::starts_with/ends_with      | **Done** |         |
| P0768R1 |                   Library support for `operator<=>` `<compare>`                    |          |         |
| P0550R2 |                                `std::remove_cvref`                                 | **Done** |         |
| P0600R1 |                      `[[nodiscard]]` in the standard library                       | **Done** |         |
| P0616R0 |                      Using `std::move` in numeric algorithms                       | **Done** |         |
| P0653R2 |                   Utility to convert a pointer to a raw pointer                    |          |         |
| P0122R7 |                                    `std::span`                                     | **Done** |         |
| P0355R7 |                               Calendar and timezone                                |  _WIP_   |         |
| P0754R2 |                                    `<version>`                                     | **Done** |         |
| P0858R0 |                          _ConstexprIterator_ requirements                          |          |         |
| P0458R2 | `contains()` member function of associative containers, e.g.`std::map::contains()` | **Done** |         |
| P0475R1 |              DR11: Guaranteed copy elision for piecewise construction              |          |         |
| P0476R2 |                                 `std::bit_cast()`                                  | **Done** |         |
| P0556R3 |                           Integral power-of-2 operations                           | **Done** |         |
| P1956R1 |                On the names of low-level bit manipulation functions                | **Done** |         |
| P0646R1 |                Improving the return value of erase-like algorithms                 |  _WIP_   |         |
| P0722R3 |                              `std::destroying_delete`                              |          |         |
| P0758R1 |                           `std::is_nothrow_convertible`                            | **Done** |         |
| P0769R2 |                     Add `std::shift_left/right` to <algorithm>                     | **Done** |         |
| P0879R0 |               Constexpr for `std::swap()` and swap related functions               | **Done** |         |
| P0887R1 |                                `std::type_identity`                                | **Done** |         |
| P0898R3 |                                  Concepts library                                  |  _WIP_   |         |
| P0318R1 |                `std::unwrap_ref_decay` and `std::unwrap_reference`                 |          |         |
| P0356R5 |                                `std::bind_front()`                                 |  _WIP_   |         |
| P0357R3 |                   `std::reference_wrapper` for incomplete types                    |          |         |
| P0482R6 |                           Library support for `char8_t`                            |          |         |
| P0591R4 |             Utility functions to implement uses-allocator construction             |          |         |
| P0602R4 |   DR17: `std::variant` and `std::optional` should propagate copy/move triviality   |  _WIP_   |         |
| P0608R3 |                    A sane `std::variant` converting constructor                    |  _WIP_   |         |
| P0771R1 |               `std::function`'s move constructor should be noexcept                |          |         |
| P0896R4 |                              The One Ranges Proposal                               |  _WIP_   |         |
| P0919R3 |                   Heterogeneous lookup for unordered containers                    |          |         |
| P0972R0 |            `<chrono>` `zero()`, `min()`, and `max()` should be noexcept            |          |         |
| P0339R6 |                   `polymorphic_allocator<>` as a vocabulary type                   |          |         |
| P0811R3 |                        `std::lerp()` and `std::midpoint()`                         | **Done** |         |
| P0325R4 |                                 `std::to_array()`                                  | **Done** |         |
| P0466R5 |            Layout-compatibility and pointer-interconvertibility traits             |          |         |
| P0553R4 |                                   Bit operations                                   | **Done** |         |
| P0631R8 |                               Mathematical constants                               | **Done** |         |
| P0784R7 |                  constexpr `std::allocator` and related utilities                  |          |         |
| P0980R1 |                              constexpr `std::string`                               |          |         |
| P0586R2 |                             Safe integral comparisons                              | **Done** |         |
