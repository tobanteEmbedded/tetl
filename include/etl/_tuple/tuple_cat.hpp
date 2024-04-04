// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_TUPLE_TUPLE_CAT_HPP
#define TETL_TUPLE_TUPLE_CAT_HPP

#include <etl/_cstddef/size_t.hpp>
#include <etl/_tuple/forward_as_tuple.hpp>
#include <etl/_tuple/tuple_like.hpp>
#include <etl/_tuple/tuple_size.hpp>
#include <etl/_type_traits/remove_reference.hpp>
#include <etl/_utility/forward.hpp>
#include <etl/_utility/index_sequence.hpp>

namespace etl {

namespace detail {

inline constexpr struct tuple_cat {
    template <etl::tuple_like T1, etl::tuple_like T2, etl::size_t... I1, etl::size_t... I2>
    [[nodiscard]] constexpr auto
    concat(T1&& t1, T2&& t2, etl::index_sequence<I1...> /*i1*/, etl::index_sequence<I2...> /*i2*/) const
    {
        using etl::get;
        return etl::forward_as_tuple(get<I1>(etl::forward<T1>(t1))..., get<I2>(etl::forward<T2>(t2))...);
    }

    template <etl::tuple_like Result>
    [[nodiscard]] constexpr auto operator()(Result&& result) const
    {
        return [&]<etl::size_t... Is>(etl::index_sequence<Is...> /*is*/) {
            using etl::get;
            return etl::tuple{get<Is>(etl::forward<Result>(result))...};
        }(etl::make_index_sequence<etl::tuple_size_v<etl::remove_reference_t<Result>>>{});
    }

    template <etl::tuple_like Result, etl::tuple_like Head, etl::tuple_like... Tail>
    [[nodiscard]] constexpr auto operator()(Result&& result, Head&& head, Tail&&... tail) const
    {
        constexpr auto idx1 = etl::make_index_sequence<etl::tuple_size_v<etl::remove_reference_t<Result>>>{};
        constexpr auto idx2 = etl::make_index_sequence<etl::tuple_size_v<etl::remove_reference_t<Head>>>{};
        return (*this)(
            concat(etl::forward<Result>(result), etl::forward<Head>(head), idx1, idx2),
            etl::forward<Tail>(tail)...
        );
    }
} tuple_cat;

} // namespace detail

template <etl::tuple_like... Tuples>
[[nodiscard]] constexpr auto tuple_cat(Tuples&&... ts)
{
    return etl::detail::tuple_cat(etl::forward<Tuples>(ts)...);
}

} // namespace etl

#endif // TETL_TUPLE_TUPLE_CAT_HPP
