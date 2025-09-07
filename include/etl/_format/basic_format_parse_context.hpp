// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2023 Tobias Hienzsch

#ifndef TETL_FORMAT_BASIC_FORMAT_PARSE_CONTEXT_HPP
#define TETL_FORMAT_BASIC_FORMAT_PARSE_CONTEXT_HPP

#include <etl/_cstddef/ptrdiff_t.hpp>
#include <etl/_cstddef/size_t.hpp>
#include <etl/_string_view/basic_string_view.hpp>

namespace etl {

template <typename CharT>
struct basic_format_parse_context {
    using char_type      = CharT;
    using const_iterator = typename basic_string_view<CharT>::const_iterator;
    using iterator       = const_iterator;

    constexpr explicit basic_format_parse_context(basic_string_view<CharT> fmt, size_t numArgs = 0) noexcept
        : _begin{fmt.begin()}
        , _end{fmt.end()}
        , _numArgs{numArgs}
    {
    }

    basic_format_parse_context(basic_format_parse_context const& other)                    = delete;
    auto operator=(basic_format_parse_context const& other) -> basic_format_parse_context& = delete;

    [[nodiscard]] constexpr auto begin() const noexcept -> const_iterator
    {
        return _begin;
    }

    [[nodiscard]] constexpr auto end() const noexcept -> const_iterator
    {
        return _end;
    }

    constexpr auto advance_to(const_iterator it) -> void
    {
        _begin = it;
    }

    [[nodiscard]] constexpr auto next_arg_id() -> size_t
    {
        return static_cast<size_t>(_nextArgId++);
    }

    constexpr auto check_arg_id(size_t /*id*/) -> void
    {
        _nextArgId = -1;
    }

private:
    // next_arg_id_  > 0 means automatic
    // next_arg_id_ == 0 means unknown
    // next_arg_id_  < 0 means manual

    iterator _begin;
    iterator _end;
    size_t _numArgs;
    ptrdiff_t _nextArgId{};
};

using format_parse_context  = basic_format_parse_context<char>;
using wformat_parse_context = basic_format_parse_context<wchar_t>;

} // namespace etl

#endif // TETL_FORMAT_BASIC_FORMAT_PARSE_CONTEXT_HPP
