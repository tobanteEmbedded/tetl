// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2023 Tobias Hienzsch

#include "testing/testing.hpp"

#if defined(TETL_ENABLE_CXX_MODULES)
import etl;
#else
    #include <etl/array.hpp>
    #include <etl/concepts.hpp>
    #include <etl/cstddef.hpp>
    #include <etl/cstdint.hpp>
    #include <etl/iterator.hpp>
#endif

template <typename T>
static constexpr auto test() -> bool
{
    CHECK_SAME_TYPE(etl::iter_value_t<typename etl::array<T, 2>::iterator>, T);
    CHECK_SAME_TYPE(etl::iter_value_t<typename etl::array<T, 2>::const_iterator>, T);
    CHECK_SAME_TYPE(etl::iter_value_t<typename etl::array<T, 2>::const_iterator>, T);

    CHECK_SAME_TYPE(etl::iter_difference_t<typename etl::array<T, 2>::iterator>, etl::ptrdiff_t);
    CHECK_SAME_TYPE(etl::iter_difference_t<typename etl::array<T, 2>::const_iterator>, etl::ptrdiff_t);
    CHECK_SAME_TYPE(etl::iter_difference_t<typename etl::array<T, 2>::const_iterator>, etl::ptrdiff_t);
    return true;
}

static constexpr auto test_all() -> bool
{
    CHECK(test<etl::int8_t>());
    CHECK(test<etl::int16_t>());
    CHECK(test<etl::int32_t>());
    CHECK(test<etl::int64_t>());
    CHECK(test<etl::uint8_t>());
    CHECK(test<etl::uint16_t>());
    CHECK(test<etl::uint32_t>());
    CHECK(test<etl::uint64_t>());
    CHECK(test<float>());
    CHECK(test<double>());
    return true;
}

auto main() -> int
{
    STATIC_CHECK(test_all());
    return 0;
}
