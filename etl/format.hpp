/*
Copyright (c) Tobias Hienzsch. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

 * Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.
 * Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND ANY
EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
DAMAGE.
*/

#ifndef TAETL_EXPERIMENTAL_FORMAT_HPP
#define TAETL_EXPERIMENTAL_FORMAT_HPP

#include "etl/detail/fmt_argument.hpp"
#include "etl/detail/fmt_context.hpp"

#include "etl/vector.hpp"

namespace etl
{
template <typename It>
using diff_t =
  typename ::etl::iterator_traits<::etl::remove_cvref_t<It>>::difference_type;

/**
 * \brief Format args according to the format string fmt, and write the result
 * to the output iterator out.
 *
 * https://en.cppreference.com/w/cpp/utility/format/format_to
 */
template <typename OutputIt, typename... Args>
auto format_to(OutputIt out, etl::string_view fmt, Args const&... args)
  -> OutputIt
{
  // TODO: Make more generic. What about other string types.
  auto ctx = format_context<::etl::static_string<32>> {out};

  // Format leading text before the first argument.
  auto const slices = detail::split_at_next_argument(fmt);
  detail::format_escaped_sequences(slices.first, ctx);

  // Save rest of format string. Supress warning if format_to was called without
  // arguments.
  auto rest = slices.second;
  ::etl::ignore_unused(rest);

  (
    [&]
    {
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
      !trailing.first.empty())
  {
    detail::format_escaped_sequences(trailing.first, ctx);
    assert(trailing.second.empty());
  }

  return ctx.out();
}

/**
 * \brief etl::format_to_n_result has no base classes, or members other than
 * out, size and implicitly declared special member functions.
 *
 * https://en.cppreference.com/w/cpp/utility/format/format_to_n
 */
template <typename Out>
struct format_to_n_result
{
  Out out;
  diff_t<Out> size;
};

/**
 * \brief Format args according to the format string fmt, and write the result
 * to the output iterator out. At most n characters are written.
 *
 * https://en.cppreference.com/w/cpp/utility/format/format_to_n
 */
template <typename OutputIter, typename... Args>
auto format_to_n(OutputIter out, diff_t<OutputIter> n, ::etl::string_view fmt,
                 Args const&... args) -> format_to_n_result<OutputIter>
{
  ::etl::ignore_unused(n);

  auto indices = ::etl::static_vector<::etl::size_t, sizeof...(args)> {};
  auto result  = format_to_n_result<OutputIter> {out, {}};

  auto writeChar = [&result](auto ch)
  {
    *result.out++ = ch;
    result.size++;
  };

  auto varStart = ::etl::size_t {};
  for (decltype(fmt)::size_type i {}; i < fmt.size(); ++i)
  {
    auto ch = fmt[i];
    if (ch == '{')
    {
      if ((fmt.size() > i + 1) && (fmt[i + 1] == '{'))
      {
        ++i;
        writeChar('{');
        continue;
      }

      varStart = i;
      continue;
    }

    if (ch == '}')
    {
      if ((fmt.size() > i + 1) && (fmt[i + 1] == '}'))
      {
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

  if (indices.size() > 0)
  {
    [[maybe_unused]] auto replaceCharAt = [n](auto output, auto pos, char val)
    {
      ::etl::ignore_unused(n);
      // assert((long)pos < n);
      output[pos] = val;
    };

    [[maybe_unused]] typename decltype(indices)::size_type i {};
    (replaceCharAt(out, indices[i++], args), ...);
  }

  return result;
}
}  // namespace etl

#endif  // TAETL_EXPERIMENTAL_FORMAT_HPP
