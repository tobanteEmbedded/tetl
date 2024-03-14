// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_TUPLE_TUPLE_CAT_HPP
#define TETL_TUPLE_TUPLE_CAT_HPP

#include <etl/_cstddef/size_t.hpp>
#include <etl/_tuple/forward_as_tuple.hpp>
#include <etl/_tuple/tuple_like.hpp>
#include <etl/_tuple/tuple_size.hpp>
#include <etl/_utility/forward.hpp>
#include <etl/_utility/index_sequence.hpp>

namespace etl {

namespace detail {

inline constexpr struct tuple_cat {
    template <typename ReturnT>
    [[nodiscard]] constexpr auto operator()(ReturnT&& ret) const
    {
        return [&]<etl::size_t... Is>(etl::index_sequence<Is...> /*is*/) {
            return etl::tuple{get<Is>(TETL_FORWARD(ret))...};
        }(etl::make_index_sequence<etl::tuple_size_v<ReturnT>>{});
    }

    template <typename ReturnT, typename FirstT, typename... Tuples>
    [[nodiscard]] constexpr auto operator()(ReturnT&& ret, FirstT&& first, Tuples&&... rest) const
    {
        auto const idx1 = etl::make_index_sequence<etl::tuple_size_v<ReturnT>>{};
        auto const idx2 = etl::make_index_sequence<etl::tuple_size_v<FirstT>>{};
        return (*this)(concat(TETL_FORWARD(ret), TETL_FORWARD(first), idx1, idx2), TETL_FORWARD(rest)...);
    }

    template <typename T1, typename T2, etl::size_t... Idx1, etl::size_t... Idx2>
    [[nodiscard]] constexpr auto
    concat(T1&& t1, T2&& t2, etl::index_sequence<Idx1...> /*is1*/, etl::index_sequence<Idx2...> /*is2*/) const
    {
        return etl::forward_as_tuple(get<Idx1>(TETL_FORWARD(t1))..., get<Idx2>(TETL_FORWARD(t2))...);
    }
} tuple_cat;

} // namespace detail

template <etl::tuple_like... Tuples>
[[nodiscard]] constexpr auto tuple_cat(Tuples&&... ts)
{
    return etl::detail::tuple_cat(TETL_FORWARD(ts)...);
}

} // namespace etl

#endif // TETL_TUPLE_TUPLE_CAT_HPP
