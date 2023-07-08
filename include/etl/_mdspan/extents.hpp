// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_MDSPAN_EXTENTS_HPP
#define TETL_MDSPAN_EXTENTS_HPP

#include <etl/_algorithm/copy.hpp>
#include <etl/_array/array.hpp>
#include <etl/_cstddef/size_t.hpp>
#include <etl/_limits/numeric_limits.hpp>
#include <etl/_span/dynamic_extent.hpp>
#include <etl/_span/span.hpp>
#include <etl/_type_traits/make_unsigned.hpp>
#include <etl/_utility/integer_sequence.hpp>

namespace etl {

template <typename IndexType, size_t... Extents>
struct extents {

    using index_type = IndexType;
    using size_type  = make_unsigned_t<IndexType>;
    using rank_type  = size_t;

private:
    [[nodiscard]] static constexpr auto _dynamic_index(rank_type i) noexcept -> rank_type
    {
        return []<size_t... Idxs>(size_t idx, integer_sequence<size_t, Idxs...>) {
            return (((Idxs < idx) ? (Extents == dynamic_extent ? 1 : 0) : 0) + ... + 0);
        }(i, make_integer_sequence<size_t, rank()> {});
    }

    [[nodiscard]] static constexpr auto _dynamic_index_inv(rank_type i) noexcept -> rank_type
    {
        // TODO: this is horrible!
        auto result = rank_type {};
        for (rank_type r { 0 }; r < rank(); ++r) {
            if (_dynamic_index(r) == i) { result = i; }
        }
        return result;
    }

    template <typename OtherSizeType>
    [[nodiscard]] static constexpr auto _index_cast(OtherSizeType&&) noexcept;

    [[nodiscard]] constexpr auto _fwd_prod_of_extents(rank_type i) const noexcept -> size_t;
    [[nodiscard]] constexpr auto _rev_prod_of_extents(rank_type i) const noexcept -> size_t;

public:
    [[nodiscard]] static constexpr auto rank() noexcept -> rank_type { return sizeof...(Extents); }

    [[nodiscard]] static constexpr auto rank_dynamic() noexcept -> rank_type
    {
        return ((rank_type(Extents == dynamic_extent)) + ... + 0);
    }

    [[nodiscard]] static constexpr auto static_extent(rank_type i) noexcept -> size_t
    {
        return []<size_t... Idxs>(size_t idx, integer_sequence<size_t, Idxs...>) {
            return (((Idxs == idx) ? Extents : 0) + ... + 0);
        }(i, make_integer_sequence<size_t, rank()> {});
    }

    [[nodiscard]] constexpr auto extent(rank_type i) const noexcept -> size_type
    {
        if constexpr (rank_dynamic() == 0) {
            return static_cast<size_type>(static_extent(i));
        } else {
            if (auto const ext = static_extent(i); ext != dynamic_extent) { return static_cast<size_type>(ext); }
            return extents_[static_cast<size_t>(_dynamic_index(i))];
        }
    }

    // [mdspan.extents.ctor], Constructors
    constexpr extents() noexcept = default;

    template <typename OtherSizeType, size_t... OtherExtents>
        requires requires {
            sizeof...(OtherExtents) == rank();
            ((OtherExtents == dynamic_extent || Extents == dynamic_extent || OtherExtents == Extents) && ...);
        }
    explicit((((Extents != dynamic_extent) && (OtherExtents == dynamic_extent)) || ...)
             || (numeric_limits<size_type>::max()
                 < numeric_limits<OtherSizeType>::max())) constexpr extents(extents<OtherSizeType,
        OtherExtents...> const& e) noexcept
    {
        if constexpr (rank_dynamic() > 0) {
            for (rank_type i { 0 }; i < rank(); ++i) {
                if (e.static_extent(i) == dynamic_extent) { extents_[_dynamic_index(i)] = e.extent(i); }
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
        auto const ext = array<size_type, sizeof...(OtherSizeTypes)> { static_cast<size_type>(es)... };
        copy(ext.begin(), ext.end(), extents_.begin());
    }

    template <typename OtherSizeType, size_t N>
    explicit(N != rank_dynamic()) constexpr extents(span<OtherSizeType, N> e) noexcept;

    template <typename OtherSizeType, size_t N>
    explicit(N != rank_dynamic()) constexpr extents(array<OtherSizeType, N> const& e) noexcept;

    // [mdspan.extents.cmp], extents comparison operators
    template <typename OtherSizeType, size_t... OtherExtents>
    friend constexpr auto operator==(extents const& lhs, extents<OtherSizeType, OtherExtents...> const& rhs) noexcept
        -> bool;

private:
    struct empty_array_t { };
    using array_t = conditional_t<rank_dynamic() == 0, empty_array_t, array<size_type, rank_dynamic()>>;

    array_t extents_ {};
};

// template <typename... Integrals>
// explicit extents(Integrals...)->see below;

} // namespace etl

#endif // TETL_MDSPAN_EXTENTS_HPP
