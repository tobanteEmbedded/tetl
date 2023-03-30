// SPDX-License-Identifier: BSL-1.0

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

    constexpr explicit basic_format_parse_context(basic_string_view<CharT> fmt, size_t num_args = 0) noexcept
        : begin_ { fmt.begin() }, end_ { fmt.end() }, num_args_ { num_args }
    {
    }

    basic_format_parse_context(basic_format_parse_context const& other)                    = delete;
    auto operator=(basic_format_parse_context const& other) -> basic_format_parse_context& = delete;

    [[nodiscard]] constexpr auto begin() const noexcept -> const_iterator { return begin_; }
    [[nodiscard]] constexpr auto end() const noexcept -> const_iterator { return end_; }
    constexpr auto advance_to(const_iterator it) -> void { begin_ = it; }

    [[nodiscard]] constexpr auto next_arg_id() -> size_t { return static_cast<size_t>(next_arg_id_++); }
    constexpr auto check_arg_id(size_t /*id*/) -> void { next_arg_id_ = -1; }

private:
    // next_arg_id_  > 0 means automatic
    // next_arg_id_ == 0 means unknown
    // next_arg_id_  < 0 means manual

    iterator begin_;
    iterator end_;
    size_t num_args_;
    ptrdiff_t next_arg_id_ {};
};

using format_parse_context  = basic_format_parse_context<char>;
using wformat_parse_context = basic_format_parse_context<wchar_t>;

} // namespace etl

#endif // TETL_FORMAT_BASIC_FORMAT_PARSE_CONTEXT_HPP
