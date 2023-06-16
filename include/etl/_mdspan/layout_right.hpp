// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_MDSPAN_LAYOUT_RIGHT_HPP
#define TETL_MDSPAN_LAYOUT_RIGHT_HPP

#include "etl/_mdspan/layout.hpp"

namespace etl {

template <typename Extents>
struct layout_right::mapping {
    using extents_type = Extents;
    using index_type   = typename extents_type::index_type;
    using size_type    = typename extents_type::size_type;
    using rank_type    = typename extents_type::rank_type;
    using layout_type  = layout_right;

    // constructors
    constexpr mapping() noexcept               = default;
    constexpr mapping(mapping const&) noexcept = default;

    constexpr mapping(extents_type const&) noexcept;

    template <typename OtherExtents>
    constexpr explicit(!is_convertible_v<OtherExtents, extents_type>) mapping(mapping<OtherExtents> const&) noexcept;

    template <typename OtherExtents>
    constexpr explicit(false /* see description */) mapping(layout_left::mapping<OtherExtents> const&) noexcept;

    template <typename OtherExtents>
    constexpr explicit(extents_type::rank() > 0) mapping(layout_stride::mapping<OtherExtents> const&) noexcept;

    constexpr mapping& operator=(mapping const&) noexcept = default;

    // observers
    [[nodiscard]] constexpr auto extents() const noexcept -> extents_type const& { return extents_; }

    [[nodiscard]] constexpr auto required_span_size() const noexcept -> index_type;

    template <typename... Indices>
    [[nodiscard]] constexpr auto operator()(Indices...) const noexcept -> index_type;

    [[nodiscard]] static constexpr auto is_always_unique() noexcept -> bool { return true; }
    [[nodiscard]] static constexpr auto is_always_exhaustive() noexcept -> bool { return true; }
    [[nodiscard]] static constexpr auto is_always_strided() noexcept -> bool { return true; }

    [[nodiscard]] static constexpr auto is_unique() noexcept -> bool { return true; }
    [[nodiscard]] static constexpr auto is_exhaustive() noexcept -> bool { return true; }
    [[nodiscard]] static constexpr auto is_strided() noexcept -> bool { return true; }

    [[nodiscard]] constexpr auto stride(rank_type) const noexcept -> index_type;

    template <typename OtherExtents>
    friend constexpr auto operator==(mapping const&, mapping<OtherExtents> const&) noexcept -> bool;

private:
    extents_type extents_ {};
};

} // namespace etl

#endif // TETL_MDSPAN_LAYOUT_RIGHT_HPP
