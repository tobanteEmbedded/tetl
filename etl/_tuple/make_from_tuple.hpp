
/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_TUPLE_MAKE_FROM_TUPLE_HPP
#define TETL_TUPLE_MAKE_FROM_TUPLE_HPP

#include "etl/_tuple/tuple.hpp"
#include "etl/_tuple/tuple_size.hpp"
#include "etl/_type_traits/declval.hpp"
#include "etl/_type_traits/is_constructible.hpp"
#include "etl/_type_traits/remove_reference.hpp"
#include "etl/_utility/forward.hpp"
#include "etl/_utility/index_sequence.hpp"

namespace etl {

namespace detail {

template <typename T, typename Tuple, size_t... I>
constexpr auto make_from_tuple_impl(Tuple&& t, index_sequence<I...> /*i*/) -> T
{
    static_assert(is_constructible_v<T, decltype(get<I>(declval<Tuple>()))...>);
    return T(get<I>(forward<Tuple>(t))...);
}

} // namespace detail

template <typename T, typename Tuple>
[[nodiscard]] constexpr auto make_from_tuple(Tuple&& t) -> T
{
    return detail::make_from_tuple_impl<T>(forward<Tuple>(t),
        make_index_sequence<tuple_size_v<remove_reference_t<Tuple>>> {});
}

} // namespace etl

#endif // TETL_TUPLE_MAKE_FROM_TUPLE_HPP
