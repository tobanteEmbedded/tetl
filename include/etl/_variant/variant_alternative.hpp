// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2021 Tobias Hienzsch

#ifndef TETL_VARIANT_VARIANT_ALTERNATIVE_HPP
#define TETL_VARIANT_VARIANT_ALTERNATIVE_HPP

#include <etl/_mpl/at.hpp>
#include <etl/_type_traits/add_const.hpp>
#include <etl/_type_traits/add_cv.hpp>
#include <etl/_type_traits/add_volatile.hpp>
#include <etl/_variant/variant_fwd.hpp>

namespace etl {

template <size_t Idx, typename... Ts>
struct variant_alternative<Idx, variant<Ts...>> {
    static_assert(Idx < sizeof...(Ts));
    using type = mpl::at_t<Idx, mpl::list<Ts...>>;
};

template <size_t I, typename T>
using variant_alternative_t = typename variant_alternative<I, T>::type;

template <size_t Idx, typename T>
struct variant_alternative<Idx, T const> {
    using type = add_const_t<variant_alternative_t<Idx, T>>;
};

template <size_t Idx, typename T>
struct variant_alternative<Idx, T volatile> {
    using type = add_volatile_t<variant_alternative_t<Idx, T>>;
};

template <size_t Idx, typename T>
struct variant_alternative<Idx, T const volatile> {
    using type = add_cv_t<variant_alternative_t<Idx, T>>;
};

} // namespace etl

#endif // TETL_VARIANT_VARIANT_ALTERNATIVE_HPP
