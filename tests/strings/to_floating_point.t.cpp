// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2024 Tobias Hienzsch

#include "testing/approx.hpp"
#include "testing/testing.hpp"

#if defined(TETL_ENABLE_CXX_MODULES)
import etl;
#else
    #include <etl/array.hpp>
    #include <etl/cstddef.hpp>
    #include <etl/iterator.hpp>
    #include <etl/string_view.hpp>
    #include <etl/strings.hpp>
#endif

template <typename T>
static constexpr auto test() -> bool
{
    using namespace etl::strings;

    CHECK_APPROX(to_floating_point<T>("0").value, T(0.0));
    CHECK_APPROX(to_floating_point<T>("10").value, T(10.0));
    CHECK_APPROX(to_floating_point<T>("100.0").value, T(100.0));
    CHECK_APPROX(to_floating_point<T>("1000.000").value, T(1000.0));
    CHECK_APPROX(to_floating_point<T>("10000").value, T(10000.0));
    CHECK_APPROX(to_floating_point<T>("999999.0").value, T(999999.0));
    CHECK_APPROX(to_floating_point<T>("9999999").value, T(9999999.0));
    CHECK_APPROX(to_floating_point<T>("   9999999").value, T(9999999.0));

    CHECK(to_floating_point<T>("0.AB").error == to_floating_point_error::invalid_input);
    CHECK(to_floating_point<T>("0.A00").error == to_floating_point_error::invalid_input);
    CHECK(to_floating_point<T>("0.99ZZ").error == to_floating_point_error::invalid_input);
    return true;
}

static constexpr auto test_all() -> bool
{
    CHECK(test<float>());
    CHECK(test<double>());
    CHECK(test<long double>());
    return true;
}

auto main() -> int
{
    STATIC_CHECK(test_all());
    return 0;
}
