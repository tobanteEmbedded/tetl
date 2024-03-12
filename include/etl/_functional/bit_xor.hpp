// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_FUNCTIONAL_BIT_XOR_HPP
#define TETL_FUNCTIONAL_BIT_XOR_HPP

#include <etl/_utility/forward.hpp>

namespace etl {

/// \brief Function object for performing bitwise XOR. Effectively calls
/// operator^ on type T.
/// https://en.cppreference.com/w/cpp/utility/functional/bit_xor
template <typename T = void>
struct bit_xor {
    [[nodiscard]] constexpr auto operator()(T const& lhs, T const& rhs) const -> T { return lhs ^ rhs; }
};

template <>
struct bit_xor<void> {
    using is_transparent = void;

    template <typename T, typename U>
    [[nodiscard]] constexpr auto operator()(T&& lhs, U&& rhs) const
        noexcept(noexcept(TETL_FORWARD(lhs) ^ TETL_FORWARD(rhs))) -> decltype(TETL_FORWARD(lhs) ^ TETL_FORWARD(rhs))
    {
        return TETL_FORWARD(lhs) ^ TETL_FORWARD(rhs);
    }
};

} // namespace etl

#endif // TETL_FUNCTIONAL_BIT_XOR_HPP
