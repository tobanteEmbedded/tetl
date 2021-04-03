#ifndef TAETL_EXPERIMENTAL_FORMAT_FORMATTER_HPP
#define TAETL_EXPERIMENTAL_FORMAT_FORMATTER_HPP

#include "etl/experimental/format/detail/context.hpp"

#include "etl/cstdlib.hpp"
#include "etl/numeric.hpp"
#include "etl/string.hpp"

namespace etl::experimental::format
{
/**
 * @brief The enabled specializations of formatter define formatting rules for a
 * given type. Enabled specializations meet the Formatter requirements.
 *
 * https://en.cppreference.com/w/cpp/utility/format/formatter
 */
template <typename T, typename CharT = char>
struct formatter;

/**
 * @brief Standard specializations for basic type char.
 */
template <>
struct formatter<char, char>
{
  template <typename FormatContext>
  constexpr auto format(char val, FormatContext& fc) -> decltype(fc.out())
  {
    auto pos = fc.out();
    *pos     = val;
    return pos++;
  }
};

/**
 * @brief Standard specializations for basic type char const*.
 */
template <>
struct formatter<char const*, char>
{
  template <typename FormatContext>
  constexpr auto format(char const* val, FormatContext& fc)
    -> decltype(fc.out())
  {
    return etl::copy(val, val + etl::strlen(val), fc.out());
  }
};

/**
 * @brief Standard specializations for basic type char array.
 */
template <::etl::size_t N>
struct formatter<char[N], char>
{
  template <typename FormatContext>
  constexpr auto format(char const* val, FormatContext& fc)
    -> decltype(fc.out())
  {
    return etl::copy(val, val + N, fc.out());
  }
};

/**
 * @brief Standard specializations for etl::string_view.
 */
template <>
struct formatter<etl::string_view, char>
{
  template <typename FormatContext>
  constexpr auto format(etl::string_view str, FormatContext& fc)
    -> decltype(fc.out())
  {
    return etl::copy(begin(str), end(str), fc.out());
  }
};

/**
 * @brief Standard specializations for etl::static_string<Capacity>.
 */
template <etl::size_t Capacity>
struct formatter<etl::static_string<Capacity>, char>
{
  template <typename FormatContext>
  constexpr auto format(etl::static_string<Capacity> const& str,
                        FormatContext& fc) -> decltype(fc.out())
  {
    return formatter<::etl::string_view>().format(str, fc);
  }
};

/**
 * @brief Standard specializations for etl::string_view.
 */
template <>
struct formatter<int, char>
{
  template <typename FormatContext>
  constexpr auto format(int val, FormatContext& fc) -> decltype(fc.out())
  {
    char str[32] {};
    ::etl::itoa(val, &str[0], 10);
    return formatter<::etl::string_view>().format(etl::string_view {str}, fc);
  }
};
}  // namespace etl::experimental::format

#endif  // TAETL_EXPERIMENTAL_FORMAT_FORMATTER_HPP
