/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_TYPE_TRAITS_ALIGNED_UNION_HPP
#define TETL_TYPE_TRAITS_ALIGNED_UNION_HPP

#include "etl/_cstddef/size_t.hpp"

namespace etl {

namespace detail {
template <typename T>
[[nodiscard]] constexpr auto vmax(T val) -> T
{
    return val;
}

template <typename T0, typename T1, typename... Ts>
[[nodiscard]] constexpr auto vmax(T0 val1, T1 val2, Ts... vs) -> T0
{
    return (val1 > val2) ? vmax(val1, vs...) : vmax(val2, vs...);
}
} // namespace detail

/// \brief Provides the nested type type, which is a trivial standard-layout
/// type of a size and alignment suitable for use as uninitialized storage for
/// an object of any of the types listed in Types. The size of the storage is at
/// least Len. aligned_union also determines the strictest (largest) alignment
/// requirement among all Types and makes it available as the constant
/// alignment_value. If sizeof...(Types) == 0 or if any of the types in Types is
/// not a complete object type, the behavior is undefined. It is
/// implementation-defined whether any extended alignment is supported. The
/// behavior of a program that adds specializations for aligned_union is
/// undefined.
template <etl::size_t Len, typename... Types>
struct aligned_union {
    static constexpr etl::size_t alignment_value = detail::vmax(alignof(Types)...);

    struct type {
        alignas(alignment_value) char storage[detail::vmax(Len, sizeof(Types)...)];
    };
};

template <etl::size_t Len, typename... Types>
using aligned_union_t = typename etl::aligned_union<Len, Types...>::type;

} // namespace etl

#endif // TETL_TYPE_TRAITS_ALIGNED_UNION_HPP