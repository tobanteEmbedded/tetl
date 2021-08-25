/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt
#ifndef TETL_NUMERIC_INNER_PRODUCT_HPP
#define TETL_NUMERIC_INNER_PRODUCT_HPP

#include "etl/_utility/move.hpp"

namespace etl {

/// \brief Computes inner product (i.e. sum of products) or performs ordered
/// map/reduce operation on the range [first1, last1) and the range beginning at
/// first2.
/// \group inner_product
/// \module Algorithm
template <typename InputIt1, typename InputIt2, typename T>
[[nodiscard]] constexpr auto inner_product(
    InputIt1 first1, InputIt1 last1, InputIt2 first2, T init) -> T
{
    for (; first1 != last1; ++first1, ++first2) {
        init = etl::move(init) + *first1 * *first2;
    }
    return init;
}

/// \group inner_product
template <typename InputIt1, typename InputIt2, typename T,
    typename BinaryOperation1, typename BinaryOperation2>
[[nodiscard]] constexpr auto inner_product(InputIt1 first1, InputIt1 last1,
    InputIt2 first2, T init, BinaryOperation1 op1, BinaryOperation2 op2) -> T
{
    for (; first1 != last1; ++first1, ++first2) {
        init = op1(etl::move(init), op2(*first1, *first2));
    }
    return init;
}

} // namespace etl

#endif // TETL_NUMERIC_INNER_PRODUCT_HPP