/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt
#ifndef TETL_NUMERIC_REDUCE_HPP
#define TETL_NUMERIC_REDUCE_HPP

#include "etl/_functional/plus.hpp"
#include "etl/_iterator/iterator_traits.hpp"
#include "etl/_numeric/accumulate.hpp"
#include "etl/_utility/move.hpp"

namespace etl {

/// \brief Similar to etl::accumulate.
/// https://en.cppreference.com/w/cpp/algorithm/reduce
/// \group reduce
/// \module Algorithm
template <typename InputIter, typename T, typename BinaryOp>
[[nodiscard]] constexpr auto reduce(InputIter first, InputIter last, T init, BinaryOp op) -> T
{
    return accumulate(first, last, init, op);
}

/// \group reduce
template <typename InputIter, typename T>
[[nodiscard]] constexpr auto reduce(InputIter first, InputIter last, T init) -> T
{
    return reduce(first, last, init, etl::plus<>());
}

/// \group reduce
template <typename InputIter>
[[nodiscard]] constexpr auto reduce(InputIter first, InputIter last) ->
    typename etl::iterator_traits<InputIter>::value_type
{
    auto init = typename etl::iterator_traits<InputIter>::value_type {};
    return reduce(first, last, init);
}

} // namespace etl

#endif // TETL_NUMERIC_REDUCE_HPP