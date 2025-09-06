// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2019 Tobias Hienzsch

#include <etl/cassert.hpp>

#if defined(TETL_ENABLE_CXX_MODULES)
import etl;
#else
    #include <etl/algorithm.hpp>
    #include <etl/vector.hpp>
#endif

auto main() -> int
{
    auto vec = etl::static_vector<double, 16>{};
    vec.push_back(1.0);
    vec.push_back(2.0);
    vec.push_back(3.0);
    vec.push_back(4.0);

    // FIND
    auto* const result1 = etl::find(vec.begin(), vec.end(), 3.0);
    assert(result1 != vec.end());

    auto* const result2 = etl::find(vec.begin(), vec.end(), 5.0);
    assert(result2 == vec.end());

    return 0;
}
