/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_EXPERIMENTAL_FORMAT_HPP
#define TETL_EXPERIMENTAL_FORMAT_HPP

#include "etl/_config/all.hpp"

#include "etl/_format/argument.hpp"
#include "etl/_format/context.hpp"
#include "etl/_type_traits/remove_cvref.hpp"
#include "etl/_vector/static_vector.hpp"

namespace etl {
template <typename It>
using diff_t =
    typename etl::iterator_traits<etl::remove_cvref_t<It>>::difference_type;

/// \brief Format args according to the format string fmt, and write the result
/// to the output iterator out.
///
/// https://en.cppreference.com/w/cpp/utility/format/format_to
///
/// \module Strings
template <typename OutputIt, typename... Args>
auto format_to(OutputIt out, etl::string_view fmt, Args const&... args)
    -> OutputIt
{
    // TODO: Make more generic. What about other string types.
    auto ctx = format_context<etl::static_string<32>> { out };

    // Format leading text before the first argument.
    auto const slices = detail::split_at_next_argument(fmt);
    detail::format_escaped_sequences(slices.first, ctx);

    // Save rest of format string. Supress warning if format_to was called
    // without arguments.
    auto rest = slices.second;
    etl::ignore_unused(rest);

    (
        [&] {
            // Format argument
            detail::format_argument(args, ctx);

            // Split format text at next argument
            auto const restSlices = detail::split_at_next_argument(rest);
            detail::format_escaped_sequences(restSlices.first, ctx);

            // Save rest of format string for the next arguments
            rest = restSlices.second;
        }(),
        ...);

    // Anything left over after the last argument.
    if (auto const trailing = detail::split_at_next_argument(rest);
        !trailing.first.empty()) {
        detail::format_escaped_sequences(trailing.first, ctx);
        TETL_ASSERT(trailing.second.empty());
    }

    return ctx.out();
}

/// \brief etl::format_to_n_result has no base classes, or members other than
/// out, size and implicitly declared special member functions.
///
/// https://en.cppreference.com/w/cpp/utility/format/format_to_n
///
/// \module Strings
template <typename Out>
struct format_to_n_result {
    Out out;
    diff_t<Out> size;
};

/// \brief Format args according to the format string fmt, and write the result
/// to the output iterator out. At most n characters are written.
///
/// https://en.cppreference.com/w/cpp/utility/format/format_to_n
///
/// \module Strings
template <typename OutputIter, typename... Args>
auto format_to_n(OutputIter out, diff_t<OutputIter> n, etl::string_view fmt,
    Args const&... args) -> format_to_n_result<OutputIter>
{
    etl::ignore_unused(n);

    auto indices = etl::static_vector<etl::size_t, sizeof...(args)> {};
    auto result  = format_to_n_result<OutputIter> { out, {} };

    auto writeChar = [&result](auto ch) {
        *result.out++ = ch;
        result.size++;
    };

    auto varStart = etl::size_t {};
    for (decltype(fmt)::size_type i {}; i < fmt.size(); ++i) {
        auto ch = fmt[i];
        if (ch == '{') {
            if ((fmt.size() > i + 1) && (fmt[i + 1] == '{')) {
                ++i;
                writeChar('{');
                continue;
            }

            varStart = i;
            continue;
        }

        if (ch == '}') {
            if ((fmt.size() > i + 1) && (fmt[i + 1] == '}')) {
                ++i;
                writeChar('}');
                continue;
            }

            indices.push_back(varStart);
            writeChar('0');
            continue;
        }

        writeChar(ch);
    }

    if (indices.size() > 0) {
        [[maybe_unused]] auto replaceCharAt
            = [n](auto output, auto pos, char val) {
                  etl::ignore_unused(n);
                  // TETL_ASSERT((long)pos < n);
                  output[pos] = val;
              };

        [[maybe_unused]] typename decltype(indices)::size_type i {};
        (replaceCharAt(out, indices[i++], args), ...);
    }

    return result;
}
} // namespace etl

#endif // TETL_EXPERIMENTAL_FORMAT_HPP
