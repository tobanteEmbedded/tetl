// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_MDSPAN_DEFAULT_ACCESSOR_HPP
#define TETL_MDSPAN_DEFAULT_ACCESSOR_HPP

#include <etl/_cstddef/size_t.hpp>
#include <etl/_type_traits/is_convertible.hpp>

namespace etl {

template <typename ElementType>
struct default_accessor {
    using offset_policy    = default_accessor;
    using element_type     = ElementType;
    using reference        = ElementType&;
    using data_handle_type = ElementType*;

    constexpr default_accessor() noexcept = default;

    template <typename OtherElementType>
        requires is_convertible_v<OtherElementType (*)[], element_type (*)[]>
    constexpr default_accessor(default_accessor<OtherElementType> /*unused*/) noexcept
    {
    }

    [[nodiscard]] constexpr auto access(data_handle_type p, size_t i) const noexcept -> reference
    {
        return p[i];
    }

    [[nodiscard]] constexpr auto offset(data_handle_type p, size_t i) const noexcept -> data_handle_type
    {
        return p + i;
    }
};

} // namespace etl

#endif // TETL_MDSPAN_DEFAULT_ACCESSOR_HPP
