// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_ARRAY_TO_ARRAY_HPP
#define TETL_ARRAY_TO_ARRAY_HPP

#include <etl/_array/array.hpp>
#include <etl/_type_traits/remove_cv.hpp>
#include <etl/_utility/index_sequence.hpp>
#include <etl/_utility/move.hpp>

namespace etl {

/// \brief Creates a array from the one dimensional built-in array a. The
/// elements of the array are copy-initialized from the corresponding element of
/// a. Copying or moving multidimensional built-in array is not supported.
/// \relates array
template <typename T, size_t N>
[[nodiscard]] constexpr auto to_array(T (&a)[N]) -> array<remove_cv_t<T>, N>
{
    return [&]<etl::size_t... I>(etl::index_sequence<I...> /*i*/) {
        return etl::array<etl::remove_cv_t<T>, N>{{a[I]...}};
    }(etl::make_index_sequence<N>{});
}

/// \relates array
template <typename T, size_t N>
[[nodiscard]] constexpr auto to_array(T (&&a)[N])
{
    return [&]<etl::size_t... I>(etl::index_sequence<I...> /*i*/) {
        return etl::array<etl::remove_cv_t<T>, N>{{etl::move(a[I])...}};
    }(etl::make_index_sequence<N>{});
}

} // namespace etl

#endif // TETL_ARRAY_TO_ARRAY_HPP
