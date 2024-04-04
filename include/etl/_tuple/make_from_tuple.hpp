
// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_TUPLE_MAKE_FROM_TUPLE_HPP
#define TETL_TUPLE_MAKE_FROM_TUPLE_HPP

#include <etl/_tuple/tuple.hpp>
#include <etl/_tuple/tuple_size.hpp>
#include <etl/_type_traits/declval.hpp>
#include <etl/_type_traits/is_constructible.hpp>
#include <etl/_type_traits/remove_reference.hpp>
#include <etl/_utility/forward.hpp>
#include <etl/_utility/index_sequence.hpp>

namespace etl {

template <typename T, typename Tuple>
[[nodiscard]] constexpr auto make_from_tuple(Tuple&& t) -> T
{
    return [&]<etl::size_t... I>(index_sequence<I...> /*i*/) {
        using etl::get;
        return T(get<I>(etl::forward<Tuple>(t))...);
    }(etl::make_index_sequence<etl::tuple_size_v<etl::remove_reference_t<Tuple>>>{});
}

} // namespace etl

#endif // TETL_TUPLE_MAKE_FROM_TUPLE_HPP
