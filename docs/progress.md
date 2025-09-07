<!-- SPDX-License-Identifier: BSL-1.0 -->
<!-- SPDX-FileCopyrightText: Copyright (C) 2024 Tobias Hienzsch -->

# Progress

Unless stated otherwise, all papers are implemented to work with the minimum C++ standard (currently C++20).

## Proposal

| Paper                                  |              Name               | Status | Comment |
| :------------------------------------- | :-----------------------------: | :----: | ------: |
| [P2988R3](https://wg21.link/P2988R3)   |       `std::optional<T&>`       | _WIP_  |         |
| [P1684R5](https://wg21.link/P1684R5)   |           `<mdarray>`           | _WIP_  |         |
| [P1144R10](https://wg21.link/P1144R10) | `std::is_trivially_relocatable` |        |         |
| [P0843R10](https://wg21.link/P0843R10) |       `<inplace_vector>`        | _WIP_  |         |

## C++26

| Paper                                  |                                                  Name                                                   |  Status  | Comment |
| :------------------------------------- | :-----------------------------------------------------------------------------------------------------: | :------: | ------: |
| [P2937R0](https://wg21.link/P2937R0)   |                                  Freestanding: removing `std::strtok`                                   | **Done** |         |
| [P2918R2](https://wg21.link/P2918R2)   |                                         Runtime format strings                                          |          |         |
| [P2868R1](https://wg21.link/P2868R1)   |                      Removing deprecated typedef `std::allocator::is_always_equal`                      |          |         |
| [P2821R5](https://wg21.link/P2821R5)   |                                            `std::span::at()`                                            |          |         |
| [P2819R2](https://wg21.link/P2819R2)   |                                 Added tuple protocol to `std::complex`                                  |  _WIP_   |         |
| [P2757R3](https://wg21.link/P2757R3)   |                                        Type checking format args                                        |          |         |
| [P2734R0](https://wg21.link/P2734R0)   | Adding the new 2022 SI prefixes on ratios: `std::quecto`, `std::ronto`, `std::ronna`, and `std::quetta` |          |         |
| [P2714R1](https://wg21.link/P2714R1)   |                `std::bind_front`, `std::bind_back`, and `std::not_fn` to NTTP callables                 |          |         |
| [P2697R1](https://wg21.link/P2697R1)   |                                 Interfacing `bitset` with `string_view`                                 | **Done** |         |
| [P2641R4](https://wg21.link/P2641R4)   |                                        `std::is_within_lifetime`                                        |          |         |
| [P2637R3](https://wg21.link/P2637R3)   |                                              Member visit                                               |          |         |
| [P2630R4](https://wg21.link/P2630R4)   |                                           `std::submdspan()`                                            |  _WIP_   |         |
| [P2592R3](https://wg21.link/P2592R3)   |                             Hashing support for `std::chrono` value classes                             |          |         |
| [P2587R3](https://wg21.link/P2587R3)   |            Arithmetic overloads of `std::to_string` and `std::to_wstring` use `std::format`             |          |         |
| [P2562R1](https://wg21.link/P2562R1)   |                                        constexpr stable sorting                                         | **Done** |         |
| [P2548R6](https://wg21.link/P2548R6)   |                                        `std::copyable_function`                                         |          |         |
| [P2546R5](https://wg21.link/P2546R5)   |                                    `<debugging>`: Debugging Support                                     |  _WIP_   |         |
| [P2545R4](https://wg21.link/P2545R4)   |                                            Read-Copy Update                                             |          |         |
| [P2538R1](https://wg21.link/P2538R1)   |                                       ADL-proof `std::projected`                                        |          |         |
| [P2530R3](https://wg21.link/P2530R3)   |                                             Hazard Pointers                                             |          |         |
| [P2510R3](https://wg21.link/P2510R3)   |                                           Formatting pointers                                           |          |         |
| [P2497R0](https://wg21.link/P2497R0)   |                        Testing for success or failure of `<charconv>` functions                         | **Done** |         |
| [P2495R3](https://wg21.link/P2495R3)   |                           Interfacing string streams with `std::string_view`                            |          |         |
| [P2447R4](https://wg21.link/P2447R4)   |                                  `std::span` over an initializer list                                   |          |         |
| [P2363R5](https://wg21.link/P2363R5)   |               Extending associative containers with the remaining heterogeneous overloads               |          |         |
| [P2264R7](https://wg21.link/P2264R7)   |                            Make `assert()` macro user friendly for C and C++                            |          |         |
| [P2013R5](https://wg21.link/P2013R5)   |                            Freestanding Language: Optional `::operator new`                             |          |         |
| [P1901R2](https://wg21.link/P1901R2)   |              Enabling the use of std::weak_ptr as keys in unordered associative containers              |          |         |
| [P1885R12](https://wg21.link/P1885R12) |                           `std::text_encoding`: text encodings identification                           |          |         |
| [P1759R6](https://wg21.link/P1759R6)   |                                     Native handles in file streams                                      |          |         |
| [P1673R13](https://wg21.link/P1673R13) |                 `<linalg>`: A free function linear algebra interface based on the BLAS                  |  _WIP_   |         |
| [P1383R2](https://wg21.link/P1383R2)   |                              More constexpr for `<cmath>` and `<complex>`                               | **Done** |         |
| [P0952R1](https://wg21.link/P0952R1)   |                            A new specification for `std::generate_canonical`                            |          |         |
| [P0792R14](https://wg21.link/P0792R14) |                           `std::function_ref`: type-erased callable reference                           |  _WIP_   |         |
| [P0543R3](https://wg21.link/P0543R3)   |                                          Saturation Arithmetic                                          |  _WIP_   |         |

## C++23

| Paper                                  |                                           Name                                           |  Status  | Comment |
| :------------------------------------- | :--------------------------------------------------------------------------------------: | :------: | ------: |
| [P2549R1](https://wg21.link/P2549R1)   |              `std::unexpected<E>` should have `error()` as member accessor               | **Done** |         |
| [P2517R1](https://wg21.link/P2517R1)   |                 Add a conditional noexcept specification to `std::apply`                 |          |         |
| [P2505R5](https://wg21.link/P2505R5)   |                          Monadic operations for `std::expected`                          |  _WIP_   |         |
| [P2445R1](https://wg21.link/P2445R1)   |                                  `std::forward_like()`                                   | **Done** |         |
| [P2417R2](https://wg21.link/P2417R2)   |                                 constexpr `std::bitset`                                  | **Done** |         |
| [P2401R0](https://wg21.link/P2401R0)   |               Add a conditional noexcept specification to `std::exchange`                | **Done** |         |
| [P2291R3](https://wg21.link/P2291R3)   |      constexpr for integral overloads of `std::to_chars()` and `std::from_chars()`.      | **Done** |         |
| [P2251R1](https://wg21.link/P2251R1)   |         Require `std::span` & `std::basic_string_view` to be _TriviallyCopyable_         | **Done** |         |
| [P2231R1](https://wg21.link/P2231R1)   |                  DR20: constexpr for `std::optional` and `std::variant`                  |          |         |
| [P2166R1](https://wg21.link/P2166R1)   | Prohibiting `std::basic_string` and `std::basic_string_view` construction from `nullptr` | **Done** |         |
| [P2162R2](https://wg21.link/P2162R2)   |               DR17: `std::visit()` for classes derived from `std::variant`               |          |         |
| [P2136R3](https://wg21.link/P2136R3)   |                                    `std::invoke_r()`                                     | **Done** |         |
| [P1989R2](https://wg21.link/P1989R2)   |                      Range constructor for `std::basic_string_view`                      |          |         |
| [P1951R1](https://wg21.link/P1951R1)   |           Default template arguments for `std::pair`'s forwarding constructor            | **Done** |         |
| [P1682R3](https://wg21.link/P1682R3)   |                                   `std::to_underlying`                                   | **Done** |         |
| [P1679R3](https://wg21.link/P1679R3)   |         `std::basic_string::contains()` and `std::basic_string_view::contains()`         | **Done** |         |
| [P1272R4](https://wg21.link/P1272R4)   |                                    `std::byteswap()`                                     | **Done** |         |
| [P1222R4](https://wg21.link/P1222R4)   |                                       `<flat_set>`                                       |  _WIP_   |         |
| [P1072R10](https://wg21.link/P1072R10) |                       `std::basic_string::resize_and_overwrite()`                        |          |         |
| [P1048R1](https://wg21.link/P1048R1)   |                                  `std::is_scoped_enum`                                   | **Done** |         |
| [P0798R8](https://wg21.link/P0798R8)   |                          Monadic operations for `std::optional`                          |  _WIP_   |         |
| [P0627R6](https://wg21.link/P0627R6)   |                                   `std::unreachable()`                                   | **Done** |         |
| [P0533R9](https://wg21.link/P0533R9)   |                         constexpr for `<cmath>` and `<cstdlib>`                          | **Done** |         |
| [P0429R9](https://wg21.link/P0429R9)   |                                       `<flat_map>`                                       |          |         |
| [P0323R12](https://wg21.link/P0323R12) |                                       `<expected>`                                       |  _WIP_   |         |

## C++20

| Paper                                |                                        Name                                        |  Status  | Comment |
| :----------------------------------- | :--------------------------------------------------------------------------------: | :------: | ------: |
| [P1956R1](https://wg21.link/P1956R1) |                On the names of low-level bit manipulation functions                | **Done** |         |
| [P0980R1](https://wg21.link/P0980R1) |                              constexpr `std::string`                               |          |         |
| [P0972R0](https://wg21.link/P0972R0) |            `<chrono>` `zero()`, `min()`, and `max()` should be noexcept            |          |         |
| [P0919R3](https://wg21.link/P0919R3) |                   Heterogeneous lookup for unordered containers                    |          |         |
| [P0898R3](https://wg21.link/P0898R3) |                                  Concepts library                                  |  _WIP_   |         |
| [P0896R4](https://wg21.link/P0896R4) |                              The One Ranges Proposal                               |  _WIP_   |         |
| [P0887R1](https://wg21.link/P0887R1) |                                `std::type_identity`                                | **Done** |         |
| [P0879R0](https://wg21.link/P0879R0) |               Constexpr for `std::swap()` and swap related functions               | **Done** |         |
| [P0858R0](https://wg21.link/P0858R0) |                          _ConstexprIterator_ requirements                          |          |         |
| [P0811R3](https://wg21.link/P0811R3) |                        `std::lerp()` and `std::midpoint()`                         | **Done** |         |
| [P0784R7](https://wg21.link/P0784R7) |                  constexpr `std::allocator` and related utilities                  |          |         |
| [P0771R1](https://wg21.link/P0771R1) |               `std::function`'s move constructor should be noexcept                |          |         |
| [P0769R2](https://wg21.link/P0769R2) |                     Add `std::shift_left/right` to <algorithm>                     | **Done** |         |
| [P0768R1](https://wg21.link/P0768R1) |                   Library support for `operator<=>` `<compare>`                    |          |         |
| [P0758R1](https://wg21.link/P0758R1) |                           `std::is_nothrow_convertible`                            | **Done** |         |
| [P0754R2](https://wg21.link/P0754R2) |                                    `<version>`                                     | **Done** |         |
| [P0722R3](https://wg21.link/P0722R3) |                              `std::destroying_delete`                              |          |         |
| [P0653R2](https://wg21.link/P0653R2) |                   Utility to convert a pointer to a raw pointer                    |          |         |
| [P0646R1](https://wg21.link/P0646R1) |                Improving the return value of erase-like algorithms                 |  _WIP_   |         |
| [P0631R8](https://wg21.link/P0631R8) |                               Mathematical constants                               | **Done** |         |
| [P0616R0](https://wg21.link/P0616R0) |                      Using `std::move` in numeric algorithms                       | **Done** |         |
| [P0608R3](https://wg21.link/P0608R3) |                    A sane `std::variant` converting constructor                    |  _WIP_   |         |
| [P0602R4](https://wg21.link/P0602R4) |   DR17: `std::variant` and `std::optional` should propagate copy/move triviality   |  _WIP_   |         |
| [P0600R1](https://wg21.link/P0600R1) |                      `[[nodiscard]]` in the standard library                       | **Done** |         |
| [P0591R4](https://wg21.link/P0591R4) |             Utility functions to implement uses-allocator construction             |          |         |
| [P0586R2](https://wg21.link/P0586R2) |                             Safe integral comparisons                              | **Done** |         |
| [P0550R2](https://wg21.link/P0550R2) |                                `std::remove_cvref`                                 | **Done** |         |
| [P0556R3](https://wg21.link/P0556R3) |                           Integral power-of-2 operations                           | **Done** |         |
| [P0553R4](https://wg21.link/P0553R4) |                                   Bit operations                                   | **Done** |         |
| [P0482R6](https://wg21.link/P0482R6) |                           Library support for `char8_t`                            |          |         |
| [P0476R2](https://wg21.link/P0476R2) |                                 `std::bit_cast()`                                  | **Done** |         |
| [P0475R1](https://wg21.link/P0475R1) |              DR11: Guaranteed copy elision for piecewise construction              |          |         |
| [P0466R5](https://wg21.link/P0466R5) |            Layout-compatibility and pointer-interconvertibility traits             |          |         |
| [P0463R1](https://wg21.link/P0463R1) |                                   `std::endian`                                    | **Done** |         |
| [P0458R2](https://wg21.link/P0458R2) | `contains()` member function of associative containers, e.g.`std::map::contains()` | **Done** |         |
| [P0457R2](https://wg21.link/P0457R2) |     String prefix and suffix checking: string(\_view) ::starts_with/ends_with      | **Done** |         |
| [P0415R1](https://wg21.link/P0415R1) |                           More constexpr for `<complex>`                           | **Done** |         |
| [P0357R3](https://wg21.link/P0357R3) |                   `std::reference_wrapper` for incomplete types                    |          |         |
| [P0356R5](https://wg21.link/P0356R5) |                                `std::bind_front()`                                 |  _WIP_   |         |
| [P0355R7](https://wg21.link/P0355R7) |                               Calendar and timezone                                |  _WIP_   |         |
| [P0339R6](https://wg21.link/P0339R6) |                   `polymorphic_allocator<>` as a vocabulary type                   |          |         |
| [P0325R4](https://wg21.link/P0325R4) |                                 `std::to_array()`                                  | **Done** |         |
| [P0318R1](https://wg21.link/P0318R1) |                `std::unwrap_ref_decay` and `std::unwrap_reference`                 |          |         |
| [P0202R3](https://wg21.link/P0202R3) |                    constexpr for `<algorithm>` and `<utility>`                     | **Done** |         |
| [P0122R7](https://wg21.link/P0122R7) |                                    `std::span`                                     | **Done** |         |

## C++17

| Paper                                |                                         Name                                         |  Status  | Comment |
| :----------------------------------- | :----------------------------------------------------------------------------------: | :------: | ------: |
| [LWG3657](https://wg21.link/LWG3657) |                       DR17: `std::hash<std::filesystem::path>`                       |          |         |
| [LWG2911](https://wg21.link/LWG2911) |                                 `std::is_aggregate`                                  | **Done** |         |
| [P0414R2](https://wg21.link/P0414R2) |               `std::shared_ptr` and `std::weak_ptr` with array support               |          |         |
| [P0358R1](https://wg21.link/P0358R1) |                               Fixes for `std::not_fn`                                | **Done** |         |
| [P0298R3](https://wg21.link/P0298R3) |                                     `std::byte`                                      | **Done** |         |
| [P0295R0](https://wg21.link/P0295R0) |                            `std::gcd()` and `std::lcm()`                             | **Done** |         |
| [P0258R2](https://wg21.link/P0258R2) |                       `std::has_unique_object_representations`                       | **Done** |         |
| [P0220R1](https://wg21.link/P0220R1) |              Adopt Library Fundamentals V1 TS Components for C++17 (R1)              |  _WIP_   |         |
| [P0220R1](https://wg21.link/P0220R1) |                                      `std::any`                                      |          |         |
| [P0220R1](https://wg21.link/P0220R1) |                                   `std::optional`                                    | **Done** |         |
| [P0220R1](https://wg21.link/P0220R1) |                             Polymorphic memory resources                             |          |         |
| [P0226R1](https://wg21.link/P0226R1) |                            Mathematical special functions                            |          |         |
| [P0218R1](https://wg21.link/P0218R1) |                                 File system library                                  |          |         |
| [P0209R2](https://wg21.link/P0209R2) |                               `std::make_from_tuple()`                               | **Done** |         |
| [P0185R1](https://wg21.link/P0185R1) |                              (nothrow-)swappable traits                              | **Done** |         |
| [P0156R2](https://wg21.link/P0156R2) |                                  `std::scoped_lock`                                  |          |         |
| [P0154R1](https://wg21.link/P0154R1) |                              Hardware interference size                              | **Done** |         |
| [P0088R3](https://wg21.link/P0088R3) |                                    `std::variant`                                    | **Done** |         |
| [P0084R2](https://wg21.link/P0084R2) | return type of `emplace` functions of some containers changed from void to reference | **Done** |         |
| [P0083R3](https://wg21.link/P0083R3) |                                Splicing Maps and Sets                                |          |         |
| [P0067R5](https://wg21.link/P0067R5) |                            Elementary string conversions                             |  _WIP_   |         |
| [P0063R3](https://wg21.link/P0063R3) |                        Major portion of C11 standard library                         |  _WIP_   |         |
| [P0025R1](https://wg21.link/P0025R1) |                                    `std::clamp()`                                    | **Done** |         |
| [P0024R2](https://wg21.link/P0024R2) |                      Parallel algorithms and execution policies                      |          |         |
| [P0013R1](https://wg21.link/P0013R1) |                             Logical operator type traits                             | **Done** |         |
| [P0006R0](https://wg21.link/P0006R0) |                            Type traits variable templates                            | **Done** |         |
| [P0005R4](https://wg21.link/P0005R4) |                                    `std::not_fn`                                     | **Done** |         |
| [N4508](https://wg21.link/N4508)     |                            `std::shared_mutex` (untimed)                             |          |         |
| [N4389](https://wg21.link/N4389)     |                                 `std::bool_constant`                                 | **Done** |         |
| [N4387](https://wg21.link/N4387)     |                        Improving `std::pair` and `std::tuple`                        | **Done** |         |
| [N4280](https://wg21.link/N4280)     |                   `std::size()`, `std::empty()` and `std::data()`                    | **Done** |         |
| [N4259](https://wg21.link/N4259)     |                             `std::uncaught_exceptions()`                             |          |         |
| [N3921](https://wg21.link/N3921)     |            `string_view`: a non-owning reference to a string, revision 7             | **Done** |         |
| [N3911](https://wg21.link/N3911)     |                                    `std::void_t`                                     | **Done** |         |

## C++14

| Paper                            |                              Name                               |  Status  | Comment |
| :------------------------------- | :-------------------------------------------------------------: | :------: | ------: |
| [N3671](https://wg21.link/N3671) | Dual-Range `std::equal`, `std::is_permutation`, `std::mismatch` | **Done** |         |
| [N3670](https://wg21.link/N3670) |                         `std::get<T>()`                         | **Done** |         |
| [N3669](https://wg21.link/N3669) |         fixing constexpr member functions without const         | **Done** |         |
| [N3668](https://wg21.link/N3668) |                         `std::exchange`                         | **Done** |         |
| [N3659](https://wg21.link/N3659) |                     std::shared_timed_mutex                     |          |         |
| [N3658](https://wg21.link/N3658) |                     `std::integer_sequence`                     | **Done** |         |
| [N3657](https://wg21.link/N3657) |                Heterogeneous associative lookup                 | **Done** |         |
| [N3656](https://wg21.link/N3656) |                       `std::make_unique`                        |          |         |
| [N3654](https://wg21.link/N3654) |                          `std::quoted`                          |          |         |
| [N3644](https://wg21.link/N3644) |                     Null forward iterators                      | **Done** |         |
| [N3642](https://wg21.link/N3642) |       User-defined literals for `<chrono>` and `<string>`       | **Done** |         |
| [N3545](https://wg21.link/N3545) |                 Improved std::integral_constant                 | **Done** |         |
| [N3471](https://wg21.link/N3471) |  constexpr for `<initializer_list>`, `<utility>` and `<tuple>`  | **Done** |         |
| [N3470](https://wg21.link/N3470) |                     constexpr for `<array>`                     | **Done** |         |
| [N3469](https://wg21.link/N3469) |                    constexpr for `<chrono>`                     | **Done** |         |
| [N3462](https://wg21.link/N3462) |                   `std::result_of` and SFINAE                   | **Done** |         |
| [N3421](https://wg21.link/N3421) |                  Transparent operator functors                  | **Done** |         |
| [N3302](https://wg21.link/N3302) |                    constexpr for `<complex>`                    | **Done** |         |
