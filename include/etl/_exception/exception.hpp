// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_EXCEPTION_EXCEPTION_HPP
#define TETL_EXCEPTION_EXCEPTION_HPP

namespace etl {

struct exception {
    constexpr exception() = default;
    constexpr explicit exception(char const* what) : _what { what } { }

    [[nodiscard]] constexpr auto what() const noexcept -> char const* { return _what; }

private:
    char const* _what { nullptr };
};

} // namespace etl

#endif // TETL_EXCEPTION_EXCEPTION_HPP
