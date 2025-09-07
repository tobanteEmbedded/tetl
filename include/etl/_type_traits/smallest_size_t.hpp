// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2024 Tobias Hienzsch

#ifndef TETL_TYPE_TRAITS_SMALLEST_SIZE_T_HPP
#define TETL_TYPE_TRAITS_SMALLEST_SIZE_T_HPP

namespace etl {

namespace detail {

template <unsigned long long N>
consteval auto determine_smallest_size_t()
{
    if constexpr (N <= static_cast<unsigned char>(-1)) {
        return static_cast<unsigned char>(0);
    } else if constexpr (N <= static_cast<unsigned short>(-1)) {
        return static_cast<unsigned short>(0);
    } else if constexpr (N <= static_cast<unsigned int>(-1)) {
        return static_cast<unsigned int>(0);
    } else if constexpr (N <= static_cast<unsigned long>(-1)) {
        return static_cast<unsigned long>(0);
    } else {
        return static_cast<unsigned long long>(0);
    }
}

} // namespace detail

/// Smallest unsigned integer type that can represent values in the range [0, N].
/// \ingroup type_traits
template <unsigned long long N>
struct smallest_size {
    using type = decltype(detail::determine_smallest_size_t<N>());
};

/// \ingroup type_traits
template <unsigned long long N>
using smallest_size_t = typename smallest_size<N>::type;

} // namespace etl

#endif // TETL_TYPE_TRAITS_SMALLEST_SIZE_T_HPP
