// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_TYPE_TRAITS_CONDITIONAL_HPP
#define TETL_TYPE_TRAITS_CONDITIONAL_HPP

namespace etl {

/// \brief Provides member typedef type, which is defined as T if B is true at
/// compile time, or as F if B is false.
template <bool B, typename T, typename F>
struct conditional {
    using type = T;
};

template <typename T, typename F>
struct conditional<false, T, F> {
    using type = F;
};

template <bool B, typename T, typename F>
using conditional_t = typename etl::conditional<B, T, F>::type;

} // namespace etl

#endif // TETL_TYPE_TRAITS_CONDITIONAL_HPP
