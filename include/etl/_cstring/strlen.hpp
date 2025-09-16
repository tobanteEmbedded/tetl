// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2021 Tobias Hienzsch

#ifndef TETL_CSTRING_STRLEN_HPP
#define TETL_CSTRING_STRLEN_HPP

#include <etl/_config/all.hpp>

#include <etl/_cstddef/size_t.hpp>
#include <etl/_strings/cstr.hpp>
#include <etl/_type_traits/is_constant_evaluated.hpp>

namespace etl {

/// Returns the length of the C string str.
/// \ingroup cstring
[[nodiscard]] constexpr auto strlen(char const* str) -> etl::size_t
{
    if (not is_constant_evaluated()) {
#if __has_builtin(__builtin_strlen)
        return __builtin_strlen(str);
#endif
    }
    return etl::detail::strlen<char, etl::size_t>(str);
}

} // namespace etl

#endif // TETL_CSTRING_STRLEN_HPP
