// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_EXCEPTION_EXCEPTION_HPP
#define TETL_EXCEPTION_EXCEPTION_HPP

namespace etl {

struct exception {
    constexpr exception() = default;
    constexpr explicit exception(char const* what) : what_ { what } { }

    [[nodiscard]] constexpr auto what() const noexcept -> char const* { return what_; }

private:
    char const* what_ { nullptr };
};

} // namespace etl

#endif // TETL_EXCEPTION_EXCEPTION_HPP
