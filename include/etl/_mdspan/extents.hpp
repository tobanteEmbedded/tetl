// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_MDSPAN_EXTENTS_HPP
#define TETL_MDSPAN_EXTENTS_HPP

#include <etl/_algorithm/transform.hpp>
#include <etl/_array/array.hpp>
#include <etl/_cstddef/size_t.hpp>
#include <etl/_limits/numeric_limits.hpp>
#include <etl/_mdspan/is_extents.hpp>
#include <etl/_span/dynamic_extent.hpp>
#include <etl/_span/span.hpp>
#include <etl/_type_traits/is_convertible.hpp>
#include <etl/_type_traits/is_nothrow_convertible.hpp>
#include <etl/_type_traits/make_unsigned.hpp>
#include <etl/_utility/cmp_not_equal.hpp>
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
        return []<etl::size_t... Idxs>(etl::size_t idx, etl::index_sequence<Idxs...> /*is*/) {
            // NOLINTNEXTLINE(bugprone-misplaced-widening-cast)
            return static_cast<rank_type>((((Idxs < idx) ? (Extents == dynamic_extent ? 1 : 0) : 0) + ... + 0));
        }(i, etl::make_index_sequence<rank()>{});
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

public:
    [[nodiscard]] static constexpr auto rank() noexcept -> rank_type { return sizeof...(Extents); }

    [[nodiscard]] static constexpr auto rank_dynamic() noexcept -> rank_type { return _rank_dynamic; }

    [[nodiscard]] static constexpr auto static_extent(rank_type i) noexcept -> etl::size_t
    {
        return _static_extents[i];
    }

    [[nodiscard]] constexpr auto extent(rank_type i) const noexcept -> index_type
    {
        if constexpr (rank_dynamic() == 0) {
            return static_cast<index_type>(static_extent(i));
        } else if constexpr (rank_dynamic() == rank()) {
            return _extents[static_cast<etl::size_t>(i)];
        } else {
            if (auto const ext = static_extent(i); ext != dynamic_extent) {
                return static_cast<index_type>(ext);
            }
            return _extents[static_cast<etl::size_t>(_dynamic_index(i))];
        }
    }

    // [mdspan.extents.ctor], Constructors
    constexpr extents() noexcept = default;

    template <typename OtherIndexType, etl::size_t... OtherExtents>
        requires(
            sizeof...(OtherExtents) == rank()
            and ((OtherExtents == dynamic_extent or Extents == dynamic_extent or OtherExtents == Extents) and ...)
        )
    explicit(
        ((Extents != dynamic_extent and OtherExtents == dynamic_extent) or ...)
        or (numeric_limits<IndexType>::max() < numeric_limits<OtherIndexType>::max())
    ) constexpr extents(extents<OtherIndexType, OtherExtents...> const& e) noexcept
    {
        if constexpr (rank_dynamic() > 0) {
            for (rank_type i{0}; i < rank(); ++i) {
                if (e.static_extent(i) == dynamic_extent) {
                    _extents[_dynamic_index(i)] = static_cast<IndexType>(e.extent(i));
                }
            }
        }
    }

    template <typename... OtherIndexTypes>
        requires(
            (is_convertible_v<OtherIndexTypes, IndexType> and ...)
            and (is_nothrow_constructible_v<IndexType, OtherIndexTypes> and ...)
            and (sizeof...(OtherIndexTypes) == rank_dynamic() or sizeof...(OtherIndexTypes) == rank())
        )
    explicit constexpr extents(OtherIndexTypes... es) noexcept
        : extents{array<IndexType, sizeof...(OtherIndexTypes)>{static_cast<IndexType>(es)...}}
    {
    }

    template <typename OtherIndexType, etl::size_t N>
        requires(
            is_convertible_v<OtherIndexType const&, IndexType>
            and is_nothrow_constructible_v<IndexType, OtherIndexType const&> and (N == rank_dynamic() or N == rank())
        )
    explicit(N != rank_dynamic()) constexpr extents(span<OtherIndexType, N> ext) noexcept
    {
        if constexpr (rank_dynamic() != 0) {
            transform(ext.begin(), ext.end(), _extents.begin(), [](auto e) { return static_cast<IndexType>(e); });
        }
    }

    template <typename OtherIndexType, etl::size_t N>
        requires(
            is_convertible_v<OtherIndexType const&, IndexType>
            and is_nothrow_constructible_v<IndexType, OtherIndexType const&> and (N == rank_dynamic() or N == rank())
        )
    explicit(N != rank_dynamic()) constexpr extents(array<OtherIndexType, N> const& e) noexcept
        : extents{span{e}}
    {
    }

    template <typename OtherIndexType, etl::size_t... OtherExtents>
    friend constexpr auto
    operator==(extents const& lhs, extents<OtherIndexType, OtherExtents...> const& rhs) noexcept -> bool
    {
        if constexpr (rank() != extents<OtherIndexType, OtherExtents...>::rank()) {
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

    template <typename OtherIndexType>
    [[nodiscard]] static constexpr auto index_cast(OtherIndexType&& i) noexcept -> IndexType
    {
        return static_cast<IndexType>(i);
    }

    [[nodiscard]] constexpr auto fwd_prod_of_extents(rank_type i) const noexcept -> size_t
    {
        if constexpr (rank() == 0) {
            return 1;
        } else {
            auto result = size_t(1);
            for (auto e = rank_type(0); e < i; ++e) {
                result *= static_cast<size_t>(extent(e));
            }
            return result;
        }
    }

    [[nodiscard]] constexpr auto rev_prod_of_extents(rank_type i) const noexcept -> size_t
    {
        auto result = size_t(1);
        for (auto e = i + 1; e < rank(); ++e) {
            result *= static_cast<size_t>(extent(e));
        }
        return result;
    }

private:
    TETL_NO_UNIQUE_ADDRESS array<IndexType, rank_dynamic()> _extents{};
};

namespace detail {

template <typename IndexType, typename Integrals>
struct dextents_impl;

template <typename IndexType, etl::size_t... Integrals>
struct dextents_impl<IndexType, etl::index_sequence<Integrals...>> {
    using type = extents<IndexType, ((void)Integrals, dynamic_extent)...>;
};

} // namespace detail

template <typename... Integrals>
    requires(etl::is_convertible_v<Integrals, etl::size_t> and ...)
extents(Integrals...) -> extents<etl::size_t, etl::size_t((Integrals(), etl::dynamic_extent))...>;

template <typename IndexType, etl::size_t Rank>
using dextents = typename detail::dextents_impl<IndexType, etl::make_index_sequence<Rank>>::type;

} // namespace etl

#endif // TETL_MDSPAN_EXTENTS_HPP
