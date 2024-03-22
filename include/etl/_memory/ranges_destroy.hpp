// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_MEMORY_RANGES_DESTROY_HPP
#define TETL_MEMORY_RANGES_DESTROY_HPP

#include <etl/_concepts/destructible.hpp>
#include <etl/_iterator/iter_value_t.hpp>
#include <etl/_memory/addressof.hpp>
#include <etl/_memory/ranges_destroy_at.hpp>
#include <etl/_ranges/begin.hpp>
#include <etl/_ranges/end.hpp>
#include <etl/_ranges/range_value_t.hpp>
#include <etl/_type_traits/is_function.hpp>

namespace etl::ranges {

inline constexpr struct destroy_fn {
    template <typename /*no-throw-input-iterator*/ I, typename /*no-throw-sentinel-for<I>*/ S>
        requires etl::destructible<etl::iter_value_t<I>>
    constexpr auto operator()(I first, S last) const noexcept -> I
    {
        for (; first != last; ++first) {
            etl::ranges::destroy_at(etl::addressof(*first));
        }
        return first;
    }

    template <typename /*no-throw-input-range*/ R>
        requires etl::destructible<etl::ranges::range_value_t<R>>
    constexpr auto operator()(R&& r) const noexcept -> auto /*etl::ranges::borrowed_iterator_t<R>*/
    {
        return (*this)(etl::ranges::begin(r), etl::ranges::end(r));
    }
} destroy;

} // namespace etl::ranges

#endif // TETL_MEMORY_RANGES_DESTROY_HPP
