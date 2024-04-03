// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_SOURCE_LOCATION_SOURCE_LOCATION_HPP
#define TETL_SOURCE_LOCATION_SOURCE_LOCATION_HPP

#include <etl/_config/all.hpp>

#include <etl/_cstdint/uint_least_t.hpp>
#include <etl/_version/language_standard.hpp>

namespace etl {

#if defined(__cpp_consteval)

/// A class representing information about the source code, such as file names,
/// line numbers, and function names
///
/// \ingroup source_location
///
/// \include source_location.cpp
struct source_location {
    [[nodiscard]] static consteval auto current(
        uint_least32_t const line   = TETL_BUILTIN_LINE(),
        uint_least32_t const column = TETL_BUILTIN_COLUMN(),
        char const* const file      = TETL_BUILTIN_FILE(),
        char const* const function  = TETL_BUILTIN_FUNCTION()
    ) noexcept -> source_location
    {
        auto result      = source_location{};
        result._line     = line;
        result._column   = column;
        result._file     = file;
        result._function = function;
        return result;
    }

    constexpr source_location() noexcept = default;

    [[nodiscard]] constexpr auto line() const noexcept -> etl::uint_least32_t { return _line; }

    [[nodiscard]] constexpr auto column() const noexcept -> etl::uint_least32_t { return _column; }

    [[nodiscard]] constexpr auto file_name() const noexcept -> char const* { return _file; }

    [[nodiscard]] constexpr auto function_name() const noexcept -> char const* { return _function; }

private:
    etl::uint_least32_t _line{};
    etl::uint_least32_t _column{};
    char const* _file     = "";
    char const* _function = "";
};

#endif

} // namespace etl

#endif // TETL_SOURCE_LOCATION_SOURCE_LOCATION_HPP
