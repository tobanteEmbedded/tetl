// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_FUNCTIONAL_BIT_AND_HPP
#define TETL_FUNCTIONAL_BIT_AND_HPP

#include <etl/_utility/forward.hpp>

namespace etl {

/// \brief Function object for performing bitwise AND. Effectively calls `operator&` on type T.
/// \details https://en.cppreference.com/w/cpp/utility/functional/bit_and
/// \ingroup functional
template <typename T = void>
struct bit_and {
    [[nodiscard]] constexpr auto operator()(T const& lhs, T const& rhs) const -> T { return lhs & rhs; }
};

/// \ingroup functional
template <>
struct bit_and<void> {
    using is_transparent = void;

    template <typename T, typename U>
    [[nodiscard]] constexpr auto operator()(T&& lhs, U&& rhs) const
        noexcept(noexcept(etl::forward<T>(lhs) & etl::forward<U>(rhs)))
            -> decltype(etl::forward<T>(lhs) & etl::forward<U>(rhs))
    {
        return etl::forward<T>(lhs) & etl::forward<U>(rhs);
    }
};

} // namespace etl

#endif // TETL_FUNCTIONAL_BIT_AND_HPP
