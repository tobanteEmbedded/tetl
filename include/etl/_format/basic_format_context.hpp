// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_FORMAT_BASIC_FORMAT_CONTEXT_HPP
#define TETL_FORMAT_BASIC_FORMAT_CONTEXT_HPP

#include <etl/_format/fmt_buffer.hpp>
#include <etl/_iterator/back_insert_iterator.hpp>
#include <etl/_warning/ignore_unused.hpp>

namespace etl {
template <typename T, typename CharT>
struct formatter;

/// \brief Provides access to formatting state consisting of the formatting
/// arguments and the output iterator.
///
/// The behavior is undefined if OutputIt does not model output_iterator<const
/// CharT&>.
///
/// https://en.cppreference.com/w/cpp/utility/format/basic_format_context
template <typename OutputIt, typename CharT>
struct basic_format_context {
    using iterator  = OutputIt;
    using char_type = CharT;

    explicit constexpr basic_format_context(OutputIt pos) noexcept : _pos {pos} { }

    template <typename T>
    using formatter_type = formatter<T, CharT>;

    /// \brief Returns the iterator to the output buffer.
    [[nodiscard]] constexpr auto out() noexcept -> iterator { return _pos; }

    /// \brief Sets the output iterator to it. After a call to advance_to,
    /// subsequent calls to out() will return a copy of it.
    constexpr auto advance_to(iterator it) noexcept -> void { _pos = it; }

private:
    OutputIt _pos;
};

/// \brief Provides access to formatting state consisting of the formatting
/// arguments and the output iterator.
///
/// \details The first template argument is an output iterator that appends to
/// etl::static_string, such as etl::back_insert_iterator<etl::static_string>.
/// Implementations are encouraged to use an iterator to type-erased buffer type
/// that supports appending to any contiguous and resizable container.
///
/// The behavior is undefined if OutputIt does not model output_iterator<const
/// CharT&>.
///
/// https://en.cppreference.com/w/cpp/utility/format/basic_format_context
using format_context  = basic_format_context<back_insert_iterator<detail::fmt_buffer<char>>, char>;
using wformat_context = basic_format_context<back_insert_iterator<detail::fmt_buffer<wchar_t>>, wchar_t>;

} // namespace etl

#endif // TETL_FORMAT_BASIC_FORMAT_CONTEXT_HPP
