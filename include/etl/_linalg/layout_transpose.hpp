// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_LINALG_LAYOUT_TRANSPOSE_HPP
#define TETL_LINALG_LAYOUT_TRANSPOSE_HPP

#include <etl/_linalg/concepts.hpp>
#include <etl/_span/dynamic_extent.hpp>

namespace etl::linalg {

namespace detail {

template <typename Extents>
using transpose_extents_t = extents<typename Extents::index_type, Extents::static_extent(1), Extents::static_extent(0)>;

template <typename Extents>
    requires(Extents::rank() == 2)
[[nodiscard]] constexpr auto transpose_extents(Extents const& e) -> transpose_extents_t<Extents>
{
    constexpr auto isDynamicE0 = Extents::static_extent(0) == dynamic_extent;
    constexpr auto isDynamicE1 = Extents::static_extent(1) == dynamic_extent;

    if constexpr (isDynamicE0) {
        if constexpr (isDynamicE1) {
            return transpose_extents_t<Extents> { e.extent(1), e.extent(0) };
        } else {
            return transpose_extents_t<Extents> { e.extent(0) };
        }
    } else {
        if constexpr (isDynamicE1) {
            return transpose_extents_t<Extents> { e.extent(1) };
        } else {
            return transpose_extents_t<Extents> {};
        }
    }
}

} // namespace detail

template <typename Layout>
struct layout_transpose {
    template <typename Extents>
        requires(Extents::rank() == 2)
    struct mapping {
    private:
        using nested_mapping_t = typename Layout::template mapping<detail::transpose_extents_t<Extents>>;
        nested_mapping_t nested_mapping_;

    public:
        using extents_type = Extents;
        using size_type    = typename extents_type::size_type;
        using layout_type  = layout_transpose;

        constexpr explicit mapping(nested_mapping_t const& map) : nested_mapping_ { map } { }

        [[nodiscard]] constexpr auto extents() const noexcept(noexcept(nested_mapping_.extents())) -> extents_type
        {
            return detail::transpose_extents(nested_mapping_.extents());
        }

        [[nodiscard]] constexpr auto required_span_size() const noexcept(noexcept(nested_mapping_.required_span_size()))
            -> size_type
        {
            return nested_mapping_.required_span_size();
        }

        template <typename IndexType, typename... Indices>
        [[nodiscard]] constexpr auto operator()(Indices... rest, IndexType i, IndexType j) const
            noexcept(noexcept(nested_mapping_(rest..., j, i))) -> typename Extents::size_type
        {
            return nested_mapping_(rest..., j, i);
        }

        [[nodiscard]] constexpr auto nested_mapping() const -> nested_mapping_t { return nested_mapping_; }

        [[nodiscard]] static constexpr auto is_always_unique() -> bool { return nested_mapping_t::is_always_unique(); }

        [[nodiscard]] static constexpr auto is_always_contiguous() -> bool
        {
            return nested_mapping_t::is_always_contiguous();
        }

        [[nodiscard]] static constexpr auto is_always_strided() -> bool
        {
            return nested_mapping_t::is_always_strided();
        }

        [[nodiscard]] constexpr auto is_unique() const noexcept(noexcept(nested_mapping_.is_unique())) -> bool
        {
            return nested_mapping_.is_unique();
        }

        [[nodiscard]] constexpr auto is_contiguous() const noexcept(noexcept(nested_mapping_.is_contiguous())) -> bool
        {
            return nested_mapping_.is_contiguous();
        }

        [[nodiscard]] constexpr auto is_strided() const noexcept(noexcept(nested_mapping_.is_strided())) -> bool
        {
            return nested_mapping_.is_strided();
        }

        [[nodiscard]] constexpr auto stride(size_t r) const noexcept(noexcept(nested_mapping_.stride(r))) -> size_type
            requires(is_always_strided())
        {
            if (r == Extents::rank() - 1) { return nested_mapping_.stride(r - 2); }
            if (r == Extents::rank() - 2) { return nested_mapping_.stride(r - 1); }
            return nested_mapping_.stride(r);
        }

        template <typename OtherExtents>
            requires(Extents::rank() == OtherExtents::rank())
        friend constexpr auto operator==(mapping const& lhs, mapping<OtherExtents> const& rhs) noexcept -> bool
        {
            return lhs.nested_mapping_ == rhs.nested_mapping_;
        }
    };
};

} // namespace etl::linalg

#endif // TETL_LINALG_LAYOUT_TRANSPOSE_HPP