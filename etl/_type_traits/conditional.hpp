/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_TYPE_TRAITS_CONDITIONAL_HPP
#define TETL_TYPE_TRAITS_CONDITIONAL_HPP

namespace etl {

/// \brief Provides member typedef type, which is defined as T if B is true at
/// compile time, or as F if B is false.
/// \group conditional
template <bool B, typename T, typename F>
struct conditional {
    using type = T;
};

/// \exclude
template <typename T, typename F>
struct conditional<false, T, F> {
    using type = F;
};

/// \group conditional
template <bool B, typename T, typename F>
using conditional_t = typename conditional<B, T, F>::type;

} // namespace etl

#endif // TETL_TYPE_TRAITS_CONDITIONAL_HPP