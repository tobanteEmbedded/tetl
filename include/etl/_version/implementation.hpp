// SPDX-License-Identifier: BSL-1.0

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

[[nodiscard]] constexpr auto is_hosted() noexcept -> bool { return current_implementation == implementation::hosted; }

[[nodiscard]] constexpr auto is_freestanding() noexcept -> bool
{
    return current_implementation == implementation::freestanding;
}
} // namespace etl

#endif // TETL_VERSION_IMPLEMENTATION_HPP
