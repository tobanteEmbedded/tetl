// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2024 Tobias Hienzsch

#ifndef TETL_MDSPAN_STRIDED_SLICE_HPP
#define TETL_MDSPAN_STRIDED_SLICE_HPP

#include <etl/_config/all.hpp>

namespace etl {

template <typename OffsetType, typename ExtentType, typename StrideType>
struct strided_slice {
    using offset_type = OffsetType;
    using extent_type = ExtentType;
    using stride_type = StrideType;

    TETL_NO_UNIQUE_ADDRESS OffsetType offset{};
    TETL_NO_UNIQUE_ADDRESS ExtentType extent{};
    TETL_NO_UNIQUE_ADDRESS StrideType stride{};
};

template <typename OffsetType, typename ExtentType, typename StrideType>
strided_slice(OffsetType, ExtentType, StrideType) -> strided_slice<OffsetType, ExtentType, StrideType>;

namespace detail {

template <typename T>
inline constexpr auto is_strided_slice = false;

template <typename OT, typename ET, typename ST>
inline constexpr auto is_strided_slice<etl::strided_slice<OT, ET, ST>> = true;

} // namespace detail

} // namespace etl

#endif // TETL_MDSPAN_STRIDED_SLICE_HPP
