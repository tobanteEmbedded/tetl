// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_MDSPAN_EXTENTS_HPP
#define TETL_MDSPAN_EXTENTS_HPP

#include <etl/_array/array.hpp>
#include <etl/_cstddef/size_t.hpp>
#include <etl/_limits/numeric_limits.hpp>
#include <etl/_span/dynamic_extent.hpp>
#include <etl/_span/span.hpp>
#include <etl/_utility/integer_sequence.hpp>

namespace etl {

template <typename SizeType, size_t... Extents>
struct extents {
    using size_type = SizeType;
    using rank_type = size_t;

    // [mdspan.extents.obs], Observers of the multidimensional index space
    [[nodiscard]] static constexpr auto rank() noexcept -> rank_type { return sizeof...(Extents); }

    [[nodiscard]] static constexpr auto rank_dynamic() noexcept -> rank_type
    {
        return ((rank_type(Extents == dynamic_extent)) + ... + 0);
    }

    [[nodiscard]] static constexpr auto static_extent(rank_type i) noexcept -> size_t
    {
        auto const impl = []<size_t... Idxs>(size_t idx, integer_sequence<size_t, Idxs...>)
        {
            return (((Idxs == idx) ? Extents : 0) + ... + 0);
        };

        return impl(i, make_integer_sequence<size_t, rank()> {});
    }

    [[nodiscard]] constexpr auto extent(rank_type i) const noexcept -> size_type
    {
        return extents_[static_cast<size_t>(i)];
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
        for (rank_type i { 0 }; i < rank(); ++i) { extents_[static_cast<size_t>(i)] = e.extents(i); }
    }

    template <typename... OtherSizeTypes>
        requires requires {
                     (is_convertible_v<OtherSizeTypes, size_type> && ...);
                     (is_nothrow_constructible_v<size_type, OtherSizeTypes> && ...)
                         and (sizeof...(OtherSizeTypes) == rank_dynamic() || sizeof...(OtherSizeTypes) == rank());
                 }
    explicit constexpr extents(OtherSizeTypes... es) noexcept
    {
        array<size_type, sizeof...(OtherSizeTypes)> { static_cast<size_type>(move(es))... };
    }

    template <typename OtherSizeType, size_t N>
    explicit(N != rank_dynamic()) constexpr extents(span<OtherSizeType, N> e) noexcept;

    template <typename OtherSizeType, size_t N>
    explicit(N != rank_dynamic()) constexpr extents(array<OtherSizeType, N> const& e) noexcept;

    // [mdspan.extents.cmp], extents comparison operators
    template <typename OtherSizeType, size_t... OtherExtents>
    friend constexpr auto operator==(extents const& lhs, extents<OtherSizeType, OtherExtents...> const& rhs) noexcept
        -> bool;

    // // [mdspan.extents.helpers], exposition only helpers
    // constexpr size_t fwd - prod - of - extents(rank_type) const noexcept; // exposition only
    // constexpr size_t rev - prod - of - extents(rank_type) const noexcept; // exposition only
    // template <typename OtherSizeType>
    //     static constexpr auto index - cast(OtherSizeType&&) noexcept; // exposition only

private:
    struct empty_dextents_t { };
    using extents_storage_t = conditional_t<rank_dynamic() == 0, empty_dextents_t, array<size_type, rank_dynamic()>>;

    // static constexpr rank_type _dynamic_index(rank_type) noexcept;     // exposition only
    // static constexpr rank_type _dynamic_index_inv(rank_type) noexcept; // exposition only

    extents_storage_t extents_ {};
};

// template <typename... Integrals>
// explicit extents(Integrals...)->see below;

} // namespace etl

#endif // TETL_MDSPAN_EXTENTS_HPP
