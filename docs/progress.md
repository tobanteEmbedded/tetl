# Progress

## C++26

|                                  Name                                  |                                       Paper                                        |  Status  | Comment |
| :--------------------------------------------------------------------: | :--------------------------------------------------------------------------------: | :------: | :-----: |
|          `std::function_ref`: type-erased callable reference           | [P0792R14](https://www.open-std.org/jtc1/sc22/wg21/docs/papers/2023/p0792r14.html) |  _WIP_   |         |
|              More constexpr for `<cmath>` and `<complex>`              |  [P1383R2](https://www.open-std.org/jtc1/sc22/wg21/docs/papers/2023/p1383r2.pdf)   | **Done** |         |
| `<linalg>`: A free function linear algebra interface based on the BLAS | [P1673R13](https://www.open-std.org/jtc1/sc22/wg21/docs/papers/2023/p1673r13.html) |  _WIP_   |         |
|        Testing for success or failure of `<charconv>` functions        |  [P2497R0](https://www.open-std.org/jtc1/sc22/wg21/docs/papers/2023/p2497r0.html)  | **Done** |         |
|                        constexpr stable sorting                        |  [P2562R1](https://www.open-std.org/jtc1/sc22/wg21/docs/papers/2022/p2562r1.pdf)   | **Done** |         |
|            Hashing support for `std::chrono` value classes             |  [P2592R3](https://www.open-std.org/jtc1/sc22/wg21/docs/papers/2023/p2592r3.html)  |          |         |
|                           `std::submdspan()`                           |  [P2630R4](https://www.open-std.org/jtc1/sc22/wg21/docs/papers/2023/p2630r4.html)  |  _WIP_   |         |
|                Interfacing `bitset` with `string_view`                 |  [P2697R1](https://www.open-std.org/jtc1/sc22/wg21/docs/papers/2023/p2697r1.pdf)   | **Done** |         |
|                 Added tuple protocol to `std::complex`                 |  [P2819R2](https://www.open-std.org/jtc1/sc22/wg21/docs/papers/2023/p2819r2.pdf)   | **Done** |         |

## C++23

|                                           Name                                           |                                       Paper                                        |  Status  | Comment |
| :--------------------------------------------------------------------------------------: | :--------------------------------------------------------------------------------: | :------: | :-----: |
|                                       `<expected>`                                       | [P0323R12](https://www.open-std.org/jtc1/sc22/wg21/docs/papers/2022/p0323r12.html) |  _WIP_   |         |
|                         constexpr for `<cmath>` and `<cstdlib>`                          |  [P0533R9](https://www.open-std.org/jtc1/sc22/wg21/docs/papers/2021/p0533r9.pdf)   | **Done** |         |
|                                   `std::unreachable()`                                   |  [P0627R6](https://www.open-std.org/jtc1/sc22/wg21/docs/papers/2021/p0627r6.pdf)   | **Done** |         |
|                          Monadic operations for `std::optional`                          |  [P0798R8](https://www.open-std.org/jtc1/sc22/wg21/docs/papers/2021/p0798r8.html)  |  _WIP_   |         |
|                                  `std::is_scoped_enum`                                   |  [P1048R1](https://www.open-std.org/jtc1/sc22/wg21/docs/papers/2020/p1048r1.pdf)   | **Done** |         |
|                       `std::basic_string::resize_and_overwrite()`                        | [P1072R10](https://www.open-std.org/jtc1/sc22/wg21/docs/papers/2021/p1072r10.html) |          |         |
|                                    `std::byteswap()`                                     |  [P1272R4](https://www.open-std.org/jtc1/sc22/wg21/docs/papers/2021/p1272r4.html)  | **Done** |         |
|         `std::basic_string::contains()` and `std::basic_string_view::contains()`         |  [P1679R3](https://www.open-std.org/jtc1/sc22/wg21/docs/papers/2020/p1679r3.html)  | **Done** |         |
|                                   `std::to_underlying`                                   |  [P1682R3](https://www.open-std.org/jtc1/sc22/wg21/docs/papers/2021/p1682r3.html)  | **Done** |         |
|           Default template arguments for `std::pair`'s forwarding constructor            |  [P1951R1](https://www.open-std.org/jtc1/sc22/wg21/docs/papers/2021/p1951r1.html)  | **Done** |         |
|                      Range constructor for `std::basic_string_view`                      |  [P1989R2](https://www.open-std.org/jtc1/sc22/wg21/docs/papers/2021/p1989r2.pdf)   |          |         |
|                                    `std::invoke_r()`                                     |  [P2136R3](https://www.open-std.org/jtc1/sc22/wg21/docs/papers/2021/p2136r3.html)  | **Done** |         |
| Prohibiting `std::basic_string` and `std::basic_string_view` construction from `nullptr` |  [P2166R1](https://www.open-std.org/jtc1/sc22/wg21/docs/papers/2020/p2166r1.html)  | **Done** |         |
|         Require `std::span` & `std::basic_string_view` to be _TriviallyCopyable_         |  [P2251R1](https://www.open-std.org/jtc1/sc22/wg21/docs/papers/2021/p2251r1.pdf)   | **Done** |         |
|               Add a conditional noexcept specification to `std::exchange`                |  [P2401R0](https://www.open-std.org/jtc1/sc22/wg21/docs/papers/2021/p2401r0.html)  | **Done** |         |
|              `std::unexpected<E>` should have `error()` as member accessor               |  [P2549R1](https://www.open-std.org/jtc1/sc22/wg21/docs/papers/2022/p2549r1.html)  | **Done** |         |
