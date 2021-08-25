/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_SOURCE_LOCATION_HPP
#define TETL_SOURCE_LOCATION_HPP

/// \file This header is part of the utility library.
/// \example source_location.cpp

#include "etl/_config/all.hpp"

#include "etl/_cstdint/uint_least_t.hpp"

namespace etl {

struct source_location {
    [[nodiscard]] static TETL_CONSTEVAL auto current(
        uint_least32_t const line   = TETL_BUILTIN_LINE(),
        uint_least32_t const column = TETL_BUILTIN_COLUMN(),
        char const* const file      = TETL_BUILTIN_FILE(),
        char const* const function  = TETL_BUILTIN_FUNCTION()) noexcept
        -> source_location
    {
        auto result      = source_location {};
        result.line_     = line;
        result.column_   = column;
        result.file_     = file;
        result.function_ = function;
        return result;
    }

    constexpr source_location() noexcept = default;

    [[nodiscard]] constexpr auto line() const noexcept -> etl::uint_least32_t
    {
        return line_;
    }

    [[nodiscard]] constexpr auto column() const noexcept -> etl::uint_least32_t
    {
        return column_;
    }

    [[nodiscard]] constexpr auto file_name() const noexcept -> char const*
    {
        return file_;
    }

    [[nodiscard]] constexpr auto function_name() const noexcept -> char const*
    {
        return function_;
    }

private:
    etl::uint_least32_t line_ {};
    etl::uint_least32_t column_ {};
    char const* file_     = "";
    char const* function_ = "";
};
} // namespace etl

#endif // TETL_SOURCE_LOCATION_HPP