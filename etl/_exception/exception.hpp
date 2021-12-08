/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_EXCEPTION_EXCEPTION_HPP
#define TETL_EXCEPTION_EXCEPTION_HPP

namespace etl {

struct exception {
    constexpr exception() = default;
    constexpr explicit exception(char const* what) : what_ { what } { }

    [[nodiscard]] auto constexpr what() const noexcept -> char const* { return what_; }

private:
    char const* what_ { nullptr };
};

} // namespace etl

#endif // TETL_EXCEPTION_EXCEPTION_HPP