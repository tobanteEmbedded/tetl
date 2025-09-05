// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_MDSPAN_SUBMDSPAN_EXTENTS_HPP
#define TETL_MDSPAN_SUBMDSPAN_EXTENTS_HPP

#include <etl/_cstddef/size_t.hpp>
#include <etl/_mdspan/extents.hpp>
#include <etl/_mdspan/full_extent.hpp>
#include <etl/_mdspan/integral_constant_like.hpp>
#include <etl/_mdspan/strided_slice.hpp>
#include <etl/_span/dynamic_extent.hpp>
#include <etl/_tuple/tuple_element.hpp>
#include <etl/_type_traits/always_false.hpp>
#include <etl/_type_traits/is_convertible.hpp>

namespace etl {

namespace detail {

template <etl::size_t K, typename Extent, typename Sk>
constexpr auto submdspan_static_extent()
{
    using IndexT = typename Extent::index_type;

    if constexpr (Extent::static_extent(Extent::rank() - K) != etl::dynamic_extent) {
        if constexpr (etl::is_convertible_v<Sk, etl::full_extent_t>) {
            return Extent::static_extent(Extent::rank() - K);
        } else if constexpr (index_pair_like<Sk, IndexT>) {
            using FirstT  = etl::tuple_element_t<0, Sk>;
            using SecondT = etl::tuple_element_t<1, Sk>;
            if constexpr (integral_constant_like<FirstT> and integral_constant_like<SecondT>) {
                return de_ice(etl::tuple_element_t<1, Sk>()) - de_ice(etl::tuple_element_t<0, Sk>());
            }
        } else if constexpr (is_strided_slice<Sk>) {
            using ExtT    = typename Sk::extent_type;
            using StrideT = typename Sk::stride_type;
            if constexpr (integral_constant_like<ExtT> and not integral_constant_like<StrideT> and ExtT() == 0) {
                return 0;
            } else if constexpr (integral_constant_like<ExtT> and integral_constant_like<StrideT>) {
                return 1 + (de_ice(ExtT()) - 1) / de_ice(StrideT());
            }
        }
    }

    return etl::dynamic_extent;
}

template <etl::size_t K, typename Extents, size_t... NewExtents>
struct submdspan_extents_builder {
    template <typename Slice, typename... SlicesAndExtents>
    static constexpr auto next(Extents const& ext, Slice const& /*unused*/, SlicesAndExtents... slicesAndExtents)
    {
        if constexpr (etl::is_convertible_v<Slice, etl::full_extent_t>) {
            return submdspan_extents_builder<
                K - 1,
                Extents,
                Extents::static_extent(Extents::rank() - K),
                NewExtents...
            >::next(ext, slicesAndExtents..., ext.extent(Extents::rank() - K));
        } else if constexpr (etl::is_convertible_v<Slice, etl::size_t>) {
            return submdspan_extents_builder<K - 1, Extents, NewExtents...>::next(ext, slicesAndExtents...);
        } else if constexpr (is_strided_slice<Slice>) {
            static_assert(etl::always_false<Slice>);
        } else {
            constexpr auto newStaticExt = submdspan_static_extent<K, Extents, Slice>();
            return submdspan_extents_builder<K - 1, Extents, newStaticExt, NewExtents...>::next(
                ext,
                slicesAndExtents...
            );
        }
    }
};

template <typename Extents, size_t... NewStaticExtents>
struct submdspan_extents_builder<0, Extents, NewStaticExtents...> {
    template <typename... NewExtents>
    static constexpr auto next(Extents const& /*unused*/, NewExtents... newExts)
    {
        return etl::extents<typename Extents::index_type, NewStaticExtents...>(newExts...);
    }
};

} // namespace detail

template <typename IndexT, etl::size_t... Extents, typename... SliceSpecifiers>
[[nodiscard]] constexpr auto submdspan_extents(etl::extents<IndexT, Extents...> const& ext, SliceSpecifiers... slices)
    requires(sizeof...(slices) == etl::extents<IndexT, Extents...>::rank())
{
    using ext_t = etl::extents<IndexT, Extents...>;
    return detail::submdspan_extents_builder<ext_t::rank(), ext_t>::next(ext, slices...);
}

} // namespace etl

#endif // TETL_MDSPAN_SUBMDSPAN_EXTENTS_HPP
