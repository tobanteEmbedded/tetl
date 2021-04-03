#ifndef ETL_DETAIL_STRING_CONVERSION_HPP
#define ETL_DETAIL_STRING_CONVERSION_HPP

#include "etl/cassert.hpp"
#include "etl/cctype.hpp"
#include "etl/warning.hpp"

namespace etl::detail
{
/**
 * @brief Credit: https://www.geeksforgeeks.org/write-your-own-atoi
 */
template <typename T>
[[nodiscard]] constexpr auto ascii_to_integer(char const* str) noexcept -> T
{
  // Iterate through all characters of input string
  // and update result take ASCII character of
  // corresponding digit and subtract the code from
  // '0' to get numerical value and multiply res
  // by 10 to shuffle digits left to update running total.
  auto res = T {0};
  for (size_t i {0}; str[i] != '\0'; ++i)
  {
    auto const digit = str[i] - '0';
    res              = res * 10 + digit;
  }
  return res;
}

/**
 * @brief Converts an integer value to a null-terminated string using the
 * specified base and stores the result in the array given by str parameter.
 *
 * @details If base is 10 and value is negative, the resulting string is
 * preceded with a minus sign (-). With any other base, value is always
 * considered unsigned.
 *
 * @todo Only base 10 is currently supported. Negative not implemented as well.
 */
template <typename T>
constexpr auto integer_to_ascii(T val, char* const buffer, int base) -> char*
{
  assert(base == 10);
  ignore_unused(base);

  auto digits10 = [](T x)
  {
    T result = 1;
    while (true)
    {
      if (x < 10) { break; }
      if (x < 100)
      {
        result += 1;
        break;
      }
      if (x < 1'000)
      {
        result += 2;
        break;
      }
      if (x < 10'000)
      {
        result += 3;
        break;
      }

      x /= 10'000;
      result += 4;
    }

    return result;
  };

  T const result = digits10(val);
  T pos          = result - 1;
  while (val >= T {10})
  {
    auto const q  = val / T {10};
    auto const r  = static_cast<char>(val % T {10});
    buffer[pos--] = static_cast<char>('0' + r);
    val           = q;
  }

  *buffer = static_cast<char>(val + '0');
  return buffer;
}

/**
 * @brief Interprets a floating point value in a byte string pointed to by str.
 * @tparam FloatT The floating point type to convert to.
 * @param str Pointer to the null-terminated byte string to be interpreted.
 * @param last Pointer to a pointer to character.
 * @return Floating point value corresponding to the contents of str on success.
 */
template <typename FloatT>
[[nodiscard]] constexpr auto
ascii_to_floating_point(const char* str, char const** last = nullptr) noexcept
  -> FloatT
{
  auto res               = FloatT {0};
  auto div               = FloatT {1};
  auto afterDecimalPoint = false;
  auto leadingSpaces     = true;

  auto const* ptr = str;
  for (; *ptr != '\0'; ++ptr)
  {
    if (isspace(*ptr) && leadingSpaces) { continue; }
    leadingSpaces = false;

    if (isdigit(*ptr))
    {
      if (!afterDecimalPoint)
      {
        res *= 10;          // Shift the previous digits to the left
        res += *ptr - '0';  // Add the new one
      }
      else
      {
        div *= 10;
        res += static_cast<FloatT>(*ptr - '0') / div;
      }
    }
    else if (*ptr == '.')
    {
      afterDecimalPoint = true;
    }
    else
    {
      break;
    }
  }

  if (last != nullptr) { *last = ptr; }

  return res;
}

}  // namespace etl::detail

#endif  // ETL_DETAIL_STRING_CONVERSION_HPP
