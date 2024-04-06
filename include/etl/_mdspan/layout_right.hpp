// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_MDSPAN_LAYOUT_RIGHT_HPP
#define TETL_MDSPAN_LAYOUT_RIGHT_HPP

#include <etl/_mdspan/extents.hpp>
#include <etl/_mdspan/is_extents.hpp>
#include <etl/_mdspan/layout.hpp>
#include <etl/_mdspan/submdspan_extents.hpp>
#include <etl/_mdspan/submdspan_mapping_result.hpp>
#include <etl/_type_traits/always_false.hpp>
#include <etl/_type_traits/is_convertible.hpp>
#include <etl/_type_traits/is_nothrow_constructible.hpp>
#include <etl/_utility/index_sequence.hpp>

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

    constexpr mapping(extents_type const& ext) noexcept
        : _extents{ext}
    {
    }

    template <typename OtherExtents>
        requires is_constructible_v<extents_type, OtherExtents>
    constexpr explicit(!is_convertible_v<OtherExtents, extents_type>)
        mapping(mapping<OtherExtents> const& other) noexcept
        : _extents{other.extents()}
    {
    }

    template <typename OtherExtents>
        requires(extents_type::rank() <= 1) && is_constructible_v<extents_type, OtherExtents>
    constexpr explicit(!is_convertible_v<OtherExtents, extents_type>)
        mapping(layout_left::mapping<OtherExtents> const& other) noexcept
        : _extents{other.extents()}
    {
    }

    template <typename OtherExtents>
    constexpr explicit(extents_type::rank() > 0) mapping(layout_stride::mapping<OtherExtents> const&) noexcept;

    constexpr auto operator=(mapping const&) noexcept -> mapping& = default;

    // observers
    [[nodiscard]] constexpr auto extents() const noexcept -> extents_type const& { return _extents; }

    [[nodiscard]] constexpr auto required_span_size() const noexcept -> index_type
    {
        return static_cast<index_type>(detail::fwd_prod_of_extents(extents(), extents_type::rank()));
    }

    template <typename... Indices>
        requires(sizeof...(Indices) == extents_type::rank()) and (is_convertible_v<Indices, index_type> and ...)
                and (is_nothrow_constructible_v<index_type, Indices> and ...)
    [[nodiscard]] constexpr auto operator()(Indices... indices) const noexcept -> index_type
    {
        auto impl = [this]<typename... IT, size_t... Is>(index_sequence<Is...> /*seq*/, IT... is) {
            auto result = index_type(0);
            ((result = static_cast<index_type>(is + static_cast<index_type>(_extents.extent(Is)) * result)), ...);
            return result;
        };

        return impl(make_index_sequence<extents_type::rank()>{}, static_cast<index_type>(indices)...);
    }

    [[nodiscard]] static constexpr auto is_always_unique() noexcept -> bool { return true; }

    [[nodiscard]] static constexpr auto is_always_exhaustive() noexcept -> bool { return true; }

    [[nodiscard]] static constexpr auto is_always_strided() noexcept -> bool { return true; }

    [[nodiscard]] static constexpr auto is_unique() noexcept -> bool { return true; }

    [[nodiscard]] static constexpr auto is_exhaustive() noexcept -> bool { return true; }

    [[nodiscard]] static constexpr auto is_strided() noexcept -> bool { return true; }

    [[nodiscard]] constexpr auto stride(rank_type) const noexcept -> index_type;

    template <typename OtherExtents>
    friend constexpr auto operator==(mapping const& lhs, mapping<OtherExtents> const& rhs) noexcept -> bool
    {
        return lhs.extents() == rhs.extents();
    }

private:
    // template <typename... SliceSpecifiers>
    // [[nodiscard]] constexpr auto submdspan_mapping_impl(SliceSpecifiers... slices) const
    // {
    //     auto sub_ext     = etl::submdspan_extents(extents(), slices...);
    //     using SubExtents = decltype(sub_ext);
    //     static_assert(sizeof(SubExtents) > 0);

    // // auto sub_strides = {};

    // if constexpr (Extents::rank() == 0) {
    //     return etl::submdspan_mapping_result {*this, 0};
    // } else {
    //     static_assert(etl::always_false<SliceSpecifiers...>);
    // }
    // }

    // template <typename... SliceSpecifiers>
    // friend constexpr auto submdspan_mapping(mapping const& src, SliceSpecifiers... slices)
    // {
    //     return src.submdspan_mapping_impl(slices...);
    // }

    TETL_NO_UNIQUE_ADDRESS extents_type _extents{};
};

} // namespace etl

#endif // TETL_MDSPAN_LAYOUT_RIGHT_HPP
