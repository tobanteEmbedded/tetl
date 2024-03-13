// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_MDSPAN_EXTENTS_HPP
#define TETL_MDSPAN_EXTENTS_HPP

#include <etl/_algorithm/copy.hpp>
#include <etl/_array/array.hpp>
#include <etl/_cstddef/size_t.hpp>
#include <etl/_limits/numeric_limits.hpp>
#include <etl/_mdspan/is_extents.hpp>
#include <etl/_span/dynamic_extent.hpp>
#include <etl/_span/span.hpp>
#include <etl/_type_traits/is_convertible.hpp>
#include <etl/_type_traits/is_nothrow_convertible.hpp>
#include <etl/_type_traits/make_unsigned.hpp>
#include <etl/_utility/cmp.hpp>
#include <etl/_utility/index_sequence.hpp>

namespace etl {

template <typename IndexType, etl::size_t... Extents>
struct extents {
    using index_type = IndexType;
    using size_type  = make_unsigned_t<IndexType>;
    using rank_type  = etl::size_t;

private:
    static constexpr auto _rank           = sizeof...(Extents);
    static constexpr auto _rank_dynamic   = ((rank_type(Extents == dynamic_extent)) + ... + 0);
    static constexpr auto _static_extents = array<etl::size_t, sizeof...(Extents)>{Extents...};

    [[nodiscard]] static constexpr auto _dynamic_index(rank_type i) noexcept -> rank_type
    {
        return []<etl::size_t... Idxs>(etl::size_t idx, integer_sequence<etl::size_t, Idxs...>) {
            return static_cast<rank_type>((((Idxs < idx) ? (Extents == dynamic_extent ? 1 : 0) : 0) + ... + 0));
        }(i, make_integer_sequence<etl::size_t, rank()>{});
    }

    [[nodiscard]] static constexpr auto _dynamic_index_inv(rank_type i) noexcept -> rank_type
    {
        // TODO: this is horrible!
        auto result = rank_type{};
        for (rank_type r{0}; r < rank(); ++r) {
            if (_dynamic_index(r) == i) {
                result = i;
            }
        }
        return result;
    }

    template <typename OtherSizeType>
    [[nodiscard]] static constexpr auto _index_cast(OtherSizeType&&) noexcept;

public:
    [[nodiscard]] static constexpr auto rank() noexcept -> rank_type { return sizeof...(Extents); }

    [[nodiscard]] static constexpr auto rank_dynamic() noexcept -> rank_type { return _rank_dynamic; }

    [[nodiscard]] static constexpr auto static_extent(rank_type i) noexcept -> etl::size_t
    {
        return _static_extents[i];
    }

    [[nodiscard]] constexpr auto extent(rank_type i) const noexcept -> size_type
    {
        if constexpr (rank_dynamic() == 0) {
            return static_cast<size_type>(static_extent(i));
        } else if constexpr (rank_dynamic() == rank()) {
            return _extents[static_cast<etl::size_t>(i)];
        } else {
            if (auto const ext = static_extent(i); ext != dynamic_extent) {
                return static_cast<size_type>(ext);
            }
            return _extents[static_cast<etl::size_t>(_dynamic_index(i))];
        }
    }

    // [mdspan.extents.ctor], Constructors
    constexpr extents() noexcept = default;

    template <typename OtherSizeType, etl::size_t... OtherExtents>
        requires requires {
            sizeof...(OtherExtents) == rank();
            ((OtherExtents == dynamic_extent || Extents == dynamic_extent || OtherExtents == Extents) && ...);
        }
    explicit(
        (((Extents != dynamic_extent) && (OtherExtents == dynamic_extent)) || ...)
        || (numeric_limits<size_type>::max() < numeric_limits<OtherSizeType>::max())
    ) constexpr extents(extents<OtherSizeType, OtherExtents...> const& e) noexcept
    {
        if constexpr (rank_dynamic() > 0) {
            for (rank_type i{0}; i < rank(); ++i) {
                if (e.static_extent(i) == dynamic_extent) {
                    _extents[_dynamic_index(i)] = e.extent(i);
                }
            }
        }
    }

    template <typename... OtherSizeTypes>
        requires requires {
            (is_convertible_v<OtherSizeTypes, size_type> && ...);
            (is_nothrow_constructible_v<size_type, OtherSizeTypes> && ...)
                and (sizeof...(OtherSizeTypes) == rank_dynamic() || sizeof...(OtherSizeTypes) == rank());
        }
    explicit constexpr extents(OtherSizeTypes... es) noexcept
    {
        auto const ext = array<size_type, sizeof...(OtherSizeTypes)>{static_cast<size_type>(es)...};
        if constexpr (rank_dynamic() != 0) {
            copy(ext.begin(), ext.end(), _extents.begin());
        }
    }

    template <typename OtherSizeType, etl::size_t N>
    explicit(N != rank_dynamic()) constexpr extents(span<OtherSizeType, N> e) noexcept;

    template <typename OtherSizeType, etl::size_t N>
    explicit(N != rank_dynamic()) constexpr extents(array<OtherSizeType, N> const& e) noexcept;

    template <typename OtherSizeType, etl::size_t... OtherExtents>
    friend constexpr auto
    operator==(extents const& lhs, extents<OtherSizeType, OtherExtents...> const& rhs) noexcept -> bool
    {
        if constexpr (rank() != extents<OtherSizeType, OtherExtents...>::rank()) {
            return false;
        } else {
            for (auto i = rank_type(0); i < rank(); ++i) {
                if (cmp_not_equal(lhs.extent(i), rhs.extent(i))) {
                    return false;
                }
            }
            return true;
        }
    }

private:
    struct empty_array_t { };

    using array_t = conditional_t<rank_dynamic() == 0, empty_array_t, array<size_type, rank_dynamic()>>;

    TETL_NO_UNIQUE_ADDRESS array_t _extents{};
};

namespace detail {

template <typename Extents>
    requires is_extents<Extents>
[[nodiscard]] constexpr auto fwd_prod_of_extents(Extents const& exts, typename Extents::rank_type i) noexcept
{
    if constexpr (Extents::rank() == 0) {
        return typename Extents::index_type(1);
    } else {
        auto result = typename Extents::index_type(1);
        for (auto e = etl::size_t(0); e < i; ++e) {
            result *= exts.extent(e);
        }
        return result;
    }
}

template <typename Extents>
    requires is_extents<Extents>
[[nodiscard]] constexpr auto rev_prod_of_extents(Extents const& exts, typename Extents::rank_type i) noexcept
{
    auto result = typename Extents::index_type(1);
    for (auto e = i + 1; e < Extents::rank(); ++e) {
        result *= exts.extent(e);
    }
    return result;
}

template <typename IndexType, typename Integrals>
struct dextents_impl;

template <typename IndexType, etl::size_t... Integrals>
struct dextents_impl<IndexType, index_sequence<Integrals...>> {
    using type = extents<IndexType, ((void)Integrals, dynamic_extent)...>;
};

} // namespace detail

template <typename... Integrals>
    requires(is_convertible_v<Integrals, etl::size_t> && ...)
extents(Integrals...) -> extents<etl::size_t, etl::size_t((Integrals(), dynamic_extent))...>;

template <typename IndexType, etl::size_t Rank>
using dextents = typename detail::dextents_impl<IndexType, make_index_sequence<Rank>>::type;

} // namespace etl

#endif // TETL_MDSPAN_EXTENTS_HPP
