/*
Copyright (c) 2019-2020, Tobias Hienzsch
All rights reserved.

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

/**
 * @file numeric.hpp
 * @example numeric.cpp
 */

#ifndef TAETL_NUMERIC_HPP
#define TAETL_NUMERIC_HPP

#include "cstddef.hpp"
#include "functional.hpp"
#include "limits.hpp"
#include "type_traits.hpp"
#include "utility.hpp"

namespace etl
{
/**
 * @brief Computes the sum of the given value init and the elements in the range
 * [first, last). Uses operator+ to sum up the elements.
 */
template <typename InputIt, typename Type>
[[nodiscard]] constexpr auto accumulate(InputIt first, InputIt last,
                                        Type init) noexcept -> Type
{
  for (; first != last; ++first) { init = move(init) + *first; }
  return init;
}

/**
 * @brief Computes the sum of the given value init and the elements in the range
 * [first, last). Uses the BinaryOperation to sum up the elements.
 */
template <typename InputIt, typename Type, typename BinaryOperation>
[[nodiscard]] constexpr auto accumulate(InputIt first, InputIt last, Type init,
                                        BinaryOperation op) noexcept -> Type
{
  for (; first != last; ++first) { init = op(move(init), *first); }
  return init;
}

/**
 * @brief Similar to etl::accumulate.
 *
 * https://en.cppreference.com/w/cpp/algorithm/reduce
 */
template <typename InputIter, typename T, typename BinaryOp>
[[nodiscard]] constexpr auto reduce(InputIter first, InputIter last, T init,
                                    BinaryOp op) -> T
{
  return accumulate(first, last, init, op);
}

/**
 * @brief Similar to etl::accumulate.
 *
 * https://en.cppreference.com/w/cpp/algorithm/reduce
 */
template <typename InputIter, typename T>
[[nodiscard]] constexpr auto reduce(InputIter first, InputIter last, T init)
  -> T
{
  return reduce(first, last, init, etl::plus<>());
}

/**
 * @brief Similar to etl::accumulate.
 *
 * https://en.cppreference.com/w/cpp/algorithm/reduce
 */
template <typename InputIter>
[[nodiscard]] constexpr auto reduce(InputIter first, InputIter last) ->
  typename etl::iterator_traits<InputIter>::value_type
{
  auto init = typename etl::iterator_traits<InputIter>::value_type {};
  return reduce(first, last, init);
}

/**
 * @brief Returns the absolute value.
 */
template <typename Type>
[[nodiscard]] constexpr auto abs(Type input) noexcept -> Type
{
  using limits = numeric_limits<Type>;
  if constexpr (limits::is_signed || !limits::is_specialized)
  {
    if (input < 0) { return static_cast<Type>(-input); }
    return input;
  }
  else
  {
    return input;
  }
}

/**
 * @brief Fills the range [first, last) with sequentially increasing values,
 * starting with value and repetitively evaluating ++value.
 */
template <typename ForwardIt, typename T>
constexpr auto iota(ForwardIt first, ForwardIt last, T value) -> void
{
  while (first != last)
  {
    *first++ = value;
    ++value;
  }
}

/**
 * @brief Computes inner product (i.e. sum of products) or performs ordered
 * map/reduce operation on the range [first1, last1) and the range beginning at
 * first2.
 *
 * @details Initializes the accumulator acc with the initial value init and then
 * modifies it with the expression acc = etl::move(acc) + *first1 * *first2,
 * then modifies again with the expression acc = etl::move(acc) + *(first1+1) *
 * *(first2+1), etc until reaching last1. For built-in meaning of + and *, this
 * computes inner product of the two ranges.
 */
template <typename InputIt1, typename InputIt2, typename T>
[[nodiscard]] constexpr auto inner_product(InputIt1 first1, InputIt1 last1,
                                           InputIt2 first2, T init) -> T
{
  for (; first1 != last1; ++first1, ++first2)
  { init = etl::move(init) + *first1 * *first2; }
  return init;
}

/**
 * @brief Computes inner product (i.e. sum of products) or performs ordered
 * map/reduce operation on the range [first1, last1) and the range beginning at
 * first2.
 *
 * @details Initializes the accumulator acc with the initial value init and then
 * modifies it with the expression acc = op1(etl::move(acc), op2(*first1,
 * *first2)), then modifies again with the expression acc = op1(etl::move(acc),
 * op2(*(first1+1),
 * *(first2+1))), etc until reaching last1.
 *
 * op1 or op2 must not invalidate any iterators, including the end iterators, or
 * modify any elements of the range involved.
 */
template <typename InputIt1, typename InputIt2, typename T,
          typename BinaryOperation1, typename BinaryOperation2>
[[nodiscard]] constexpr auto
inner_product(InputIt1 first1, InputIt1 last1, InputIt2 first2, T init,
              BinaryOperation1 op1, BinaryOperation2 op2) -> T
{
  for (; first1 != last1; ++first1, ++first2)
  { init = op1(etl::move(init), op2(*first1, *first2)); }
  return init;
}

/**
 * @brief Computes the partial sums of the elements in the subranges of the
 * range [first, last) and writes them to the range beginning at destination.
 * This version uses the given binary function op, both applying etl::move to
 * their operands on the left hand side.
 *
 * @details BinaryFunction must not invalidate any iterators, including the end
 * iterators, or modify any elements of the range involved.
 *
 * https://en.cppreference.com/w/cpp/algorithm/partial_sum
 *
 * @return Iterator to the element past the last element written.
 */
template <typename InputIt, typename OutputIt, typename BinaryOperation>
constexpr auto partial_sum(InputIt first, InputIt last, OutputIt destination,
                           BinaryOperation op) -> OutputIt
{
  if (first == last) { return destination; }

  auto sum     = *first;
  *destination = sum;

  while (++first != last)
  {
    sum            = op(etl::move(sum), *first);
    *++destination = sum;
  }

  return ++destination;
}

/**
 * @brief Computes the partial sums of the elements in the subranges of the
 * range [first, last) and writes them to the range beginning at destination.
 * This version uses operator+ to sum up the elements.
 *
 * @details BinaryFunction must not invalidate any iterators, including the end
 * iterators, or modify any elements of the range involved.
 *
 * https://en.cppreference.com/w/cpp/algorithm/partial_sum
 *
 * @return Iterator to the element past the last element written.
 */
template <typename InputIt, typename OutputIt>
constexpr auto partial_sum(InputIt first, InputIt last, OutputIt destination)
  -> OutputIt
{
  return etl::partial_sum(first, last, destination, etl::plus<>());
}

/**
 * @brief Computes the greatest common divisor of the integers m and n.
 *
 * @return If both m and n are zero, returns zero. Otherwise, returns the
 * greatest common divisor of |m| and |n|.
 */
template <typename M, typename N>
[[nodiscard]] constexpr auto gcd(M m, N n) noexcept -> etl::common_type_t<M, N>
{
  if (n == 0) { return m; }
  return gcd(n, m % n);
}

/**
 * @brief Computes the least common multiple of the integers m and n.
 *
 * @return If either m or n is zero, returns zero. Otherwise, returns the least
 * common multiple of |m| and |n|.
 */
template <
  typename M, typename N,
  TAETL_REQUIRES_(
    (is_integral_v<
       M> && !is_same_v<M, bool> && is_integral_v<N> && !is_same_v<N, bool>))>
[[nodiscard]] constexpr auto lcm(M m, N n) ->

  etl::common_type_t<M, N>
{
  return (m * n) / gcd(m, n);
}

/**
 * @brief Returns half the sum of a + b. If the sum is odd, the result is
 * rounded towards a.
 *
 * @details CppCon 2019: Marshall Clow "midpoint? How Hard Could it Be?”
 *
 * https://www.youtube.com/watch?v=sBtAGxBh-XI
 *
 * https://en.cppreference.com/w/cpp/numeric/midpoint
 */
template <typename Int,
          TAETL_REQUIRES_((is_integral_v<Int> && !is_same_v<Int, bool>))>
constexpr auto midpoint(Int a, Int b) noexcept -> Int
{
  using U = make_unsigned_t<Int>;

  auto sign = 1;
  auto m    = static_cast<U>(a);
  auto M    = static_cast<U>(b);

  if (a > b)
  {
    sign = -1;
    m    = static_cast<U>(b);
    M    = static_cast<U>(a);
  }

  return static_cast<Int>(
    a + static_cast<Int>(sign * static_cast<Int>(U(M - m) >> 1)));
}

/**
 * @brief Returns half the sum of a + b. If the sum is odd, the result is
 * rounded towards a.
 *
 * @details CppCon 2019: Marshall Clow "midpoint? How Hard Could it Be?”
 *
 * https://www.youtube.com/watch?v=sBtAGxBh-XI
 *
 * https://en.cppreference.com/w/cpp/numeric/midpoint
 */
template <typename Float, TAETL_REQUIRES_(is_floating_point_v<Float>)>
constexpr auto midpoint(Float a, Float b) noexcept -> Float
{
  auto const lo = numeric_limits<Float>::min() * 2;
  auto const hi = numeric_limits<Float>::max() / 2;

  if (etl::abs(a) <= hi && etl::abs(b) <= hi) { return (a + b) / 2; }

  if (etl::abs(a) < lo) { return a + b / 2; }

  if (etl::abs(b) < lo) { return a / 2 + b; }

  return a / 2 + b / 2;
}

/**
 * @brief Returns half the sum of a + b. If the sum is odd, the result is
 * rounded towards a.
 *
 * @details CppCon 2019: Marshall Clow "midpoint? How Hard Could it Be?”
 *
 * https://www.youtube.com/watch?v=sBtAGxBh-XI
 *
 * https://en.cppreference.com/w/cpp/numeric/midpoint
 */
template <typename Pointer, TAETL_REQUIRES_(is_pointer_v<Pointer>)>
constexpr auto midpoint(Pointer a, Pointer b) noexcept -> Pointer
{
  return a + midpoint(ptrdiff_t {0}, b - a);
}

}  // namespace etl

#endif  // TAETL_NUMERIC_HPP