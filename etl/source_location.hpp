// Copyright (c) Tobias Hienzsch. All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
//  * Redistributions of source code must retain the above copyright notice,
//    this list of conditions and the following disclaimer.
//  * Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR ANY
// DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
// LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
// OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
// DAMAGE.

#ifndef TETL_SOURCE_LOCATION_HPP
#define TETL_SOURCE_LOCATION_HPP

#include "etl/version.hpp"

#include "etl/cstdint.hpp"

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
    ::etl::uint_least32_t line_ {};
    ::etl::uint_least32_t column_ {};
    char const* file_     = "";
    char const* function_ = "";
};
} // namespace etl

#endif // TETL_SOURCE_LOCATION_HPP