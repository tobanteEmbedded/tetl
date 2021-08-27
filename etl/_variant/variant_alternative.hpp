/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_VARIANT_VARIANT_ALTERNATIVE_HPP
#define TETL_VARIANT_VARIANT_ALTERNATIVE_HPP

#include "etl/_type_traits/add_const.hpp"
#include "etl/_type_traits/add_cv.hpp"
#include "etl/_type_traits/add_volatile.hpp"
#include "etl/_type_traits/type_pack_element.hpp"
#include "etl/_variant/variant_fwd.hpp"

namespace etl {

template <etl::size_t Idx, typename... Ts>
struct variant_alternative<Idx, etl::variant<Ts...>> {
    static_assert(Idx < sizeof...(Ts));
    using type = type_pack_element_t<Idx, Ts...>;
};

template <etl::size_t I, typename T>
using variant_alternative_t = typename variant_alternative<I, T>::type;

template <etl::size_t Idx, typename T>
struct variant_alternative<Idx, T const> {
    using type = etl::add_const_t<variant_alternative_t<Idx, T>>;
};
template <etl::size_t Idx, typename T>
struct variant_alternative<Idx, T volatile> {
    using type = etl::add_volatile_t<variant_alternative_t<Idx, T>>;
};
template <etl::size_t Idx, typename T>
struct variant_alternative<Idx, T const volatile> {
    using type = etl::add_cv_t<variant_alternative_t<Idx, T>>;
};

} // namespace etl

#endif // TETL_VARIANT_VARIANT_ALTERNATIVE_HPP