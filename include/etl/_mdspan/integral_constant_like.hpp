// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_MDSPAN_INTEGRAL_CONSTANT_LIKE_HPP
#define TETL_MDSPAN_INTEGRAL_CONSTANT_LIKE_HPP

#include <etl/_concepts/convertible_to.hpp>
#include <etl/_cstddef/size_t.hpp>
#include <etl/_mdspan/strided_slice.hpp>
#include <etl/_type_traits/always_false.hpp>
#include <etl/_type_traits/bool_constant.hpp>
#include <etl/_type_traits/is_integral.hpp>
#include <etl/_type_traits/is_same.hpp>
#include <etl/_type_traits/remove_const.hpp>

namespace etl::detail {

template <typename T>
concept pair_like = true;

template <typename T, typename IndexType>
concept index_pair_like =                                          //
    pair_like<T>                                                   //
    and etl::convertible_to<etl::tuple_element_t<0, T>, IndexType> //
    and etl::convertible_to<etl::tuple_element_t<1, T>, IndexType> //
    ;

template <typename T>
concept integral_constant_like =                                                    //
    etl::is_integral_v<decltype(T::value)>                                          //
    and not etl::is_same_v<bool, etl::remove_const_t<decltype(T::value)>>           //
    and etl::convertible_to<T, decltype(T::value)>                                  //
    /* and etl::equality_comparable_with<T, decltype(T::value)>   */                //
    and etl::bool_constant<T() == T::value>::value                                  //
    and etl::bool_constant<static_cast<decltype(T::value)>(T()) == T::value>::value //
    ;

template <typename T>
[[nodiscard]] constexpr auto de_ice(T val) -> T
{
    return val;
}

template <integral_constant_like T>
[[nodiscard]] constexpr auto de_ice(T /*unused*/)
{
    return T::value;
}

template <etl::size_t K>
[[nodiscard]] constexpr auto nth_slice_specifier(auto first, auto... rest)
{
    if constexpr (K == 0) {
        return first;
    } else {
        nth_slice_specifier<K - 1>(rest...);
    }
}

template <typename IndexType, etl::size_t K, typename... SliceSpecifiers>
[[nodiscard]] constexpr auto submdspan_first(SliceSpecifiers... slices) -> IndexType
{
    auto sk  = nth_slice_specifier<K>(slices...);
    using Sk = decltype(sk);

    if constexpr (etl::convertible_to<Sk, IndexType>) {
        return static_cast<IndexType>(sk);
    } else if constexpr (index_pair_like<Sk, IndexType>) {
        return static_cast<IndexType>(get<0>(sk));
    } else if constexpr (is_strided_slice<Sk>) {
        return static_cast<IndexType>(de_ice(sk.offset));
    } else {
        return static_cast<IndexType>(0);
    }
}

template <etl::size_t K, typename Extents, typename... SliceSpecifiers>
[[nodiscard]] constexpr auto submdspan_last(Extents const& src, SliceSpecifiers... slices)
{
    auto sk         = nth_slice_specifier<K>(slices...);
    using Sk        = decltype(sk);
    using IndexType = typename Extents::index_type;

    if constexpr (etl::convertible_to<Sk, IndexType>) {
        return static_cast<IndexType>(de_ice(sk)) + IndexType(1);
    } else if constexpr (index_pair_like<Sk, IndexType>) {
        return static_cast<IndexType>(get<1>(sk));
    } else if constexpr (is_strided_slice<Sk>) {
        return static_cast<IndexType>(de_ice(sk.offset) + de_ice(sk.extent));
    } else {
        return static_cast<IndexType>(src.extent(K));
    }
}

// template <typename IndexType, size_t N, typename... SliceSpecifiers>
// [[nodiscard]] constexpr auto src_indices(array<IndexType, N> const& indices, SliceSpecifiers... slices)
//     -> array<IndexType, sizeof...(SliceSpecifiers)>
// {
// }

} // namespace etl::detail

#endif // TETL_MDSPAN_INTEGRAL_CONSTANT_LIKE_HPP
