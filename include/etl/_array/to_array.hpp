/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_ARRAY_TO_ARRAY_HPP
#define TETL_ARRAY_TO_ARRAY_HPP

#include "etl/_array/array.hpp"
#include "etl/_type_traits/remove_cv.hpp"
#include "etl/_utility/index_sequence.hpp"
#include "etl/_utility/move.hpp"

namespace etl {

namespace detail {
template <typename T, size_t N, size_t... I>
[[nodiscard]] constexpr auto to_array_impl(T (&a)[N], index_sequence<I...> /*unused*/) -> array<remove_cv_t<T>, N>
{
    return { { a[I]... } };
}

template <typename T, size_t N, size_t... I>
[[nodiscard]] constexpr auto to_array_impl(T (&&a)[N], index_sequence<I...> /*unused*/) -> array<remove_cv_t<T>, N>
{
    return { { move(a[I])... } };
}

} // namespace detail

/// \brief Creates a array from the one dimensional built-in array a. The
/// elements of the array are copy-initialized from the corresponding element of
/// a. Copying or moving multidimensional built-in array is not supported.
template <typename T, size_t N>
[[nodiscard]] constexpr auto to_array(T (&a)[N]) -> array<remove_cv_t<T>, N>
{
    return detail::to_array_impl(a, make_index_sequence<N> {});
}

template <typename T, size_t N>
[[nodiscard]] constexpr auto to_array(T (&&a)[N])
{
    return detail::to_array_impl(move(a), make_index_sequence<N> {});
}

} // namespace etl

#endif // TETL_ARRAY_TO_ARRAY_HPP
