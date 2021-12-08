/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_VERSION_IMPLEMENTATION_HPP
#define TETL_VERSION_IMPLEMENTATION_HPP

namespace etl {

enum struct implementation {
    freestanding = 0,
    hosted       = 1,
};

#if defined(__STDC_HOSTED__)
inline constexpr auto current_implementation = implementation::hosted;
#else
inline constexpr auto current_implementation = implementation::freestanding;
#endif

[[nodiscard]] auto constexpr is_hosted() noexcept -> bool { return current_implementation == implementation::hosted; }

[[nodiscard]] auto constexpr is_freestanding() noexcept -> bool
{
    return current_implementation == implementation::freestanding;
}
} // namespace etl

#endif // TETL_VERSION_IMPLEMENTATION_HPP