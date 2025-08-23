// SPDX-License-Identifier: BSL-1.0

#include "testing/testing.hpp"

#if defined(TETL_ENABLE_CXX_MODULES)
import etl;
#else
    #include <etl/cstddef.hpp>
    #include <etl/iterator.hpp>
    #include <etl/string.hpp>
    #include <etl/string_view.hpp>
#endif

static constexpr auto test() -> bool
{
    using namespace etl::literals;
    auto const npos = etl::string_view::npos;

    // contains
    CHECK("test"_sv.contains('t'));
    CHECK("test"_sv.contains("t"_sv));
    CHECK("test"_sv.contains("te"_sv));
    CHECK("test"_sv.contains("tes"_sv));
    CHECK("test"_sv.contains("test"_sv));
    CHECK("test"_sv.contains("test"));
    CHECK_FALSE("test"_sv.contains("testt"));

    // starts_with
    CHECK("test"_sv.starts_with("t"_sv));
    CHECK("test"_sv.starts_with("te"_sv));
    CHECK("test"_sv.starts_with("tes"_sv));
    CHECK("test"_sv.starts_with("test"_sv));

    CHECK_FALSE("test"_sv.starts_with("f"_sv));
    CHECK_FALSE("test"_sv.starts_with("fo"_sv));
    CHECK_FALSE("test"_sv.starts_with("foo"_sv));

    CHECK_FALSE("test"_sv.starts_with("f test"_sv));
    CHECK_FALSE("test"_sv.starts_with("fo test"_sv));
    CHECK_FALSE("test"_sv.starts_with("foo test"_sv));

    CHECK("abc"_sv.starts_with('a'));
    CHECK_FALSE("abc"_sv.starts_with('b'));
    CHECK_FALSE("abc"_sv.starts_with('x'));

    CHECK("abc"_sv.starts_with("a"));
    CHECK("abc"_sv.starts_with("ab"));
    CHECK("abc"_sv.starts_with("abc"));
    CHECK_FALSE("abc"_sv.starts_with("f"));
    CHECK_FALSE("abc"_sv.starts_with("fo"));
    CHECK_FALSE("abc"_sv.starts_with("foo"));

    // ends_width
    CHECK("test"_sv.ends_with("t"_sv));
    CHECK("test"_sv.ends_with("st"_sv));
    CHECK("test"_sv.ends_with("est"_sv));
    CHECK("test"_sv.ends_with("test"_sv));

    CHECK("abc"_sv.ends_with('c'));
    CHECK_FALSE("abc"_sv.ends_with('a'));

    CHECK("abc"_sv.ends_with("c"));
    CHECK("abc"_sv.ends_with("bc"));
    CHECK("abc"_sv.ends_with("abc"));

    // find
    CHECK("test"_sv.find("t"_sv) == 0);
    CHECK("test"_sv.find("est"_sv) == 1);

    CHECK("test"_sv.find("st"_sv, 1) == 2);
    CHECK("test"_sv.find("st"_sv, 2) == 2);

    CHECK("test"_sv.find('t') == 0);
    CHECK("test"_sv.find('e') == 1);

    CHECK("test"_sv.find('s') == 2);
    CHECK("test"_sv.find('s', 2) == 2);

    CHECK("test"_sv.find("t", 0, 1) == 0);
    CHECK("test"_sv.find("est", 0, 3) == 1);

    CHECK("test"_sv.find("x", 0, 1) == npos);
    CHECK("test"_sv.find("foo", 0, 3) == npos);

    CHECK("test"_sv.find("t", 0) == 0);
    CHECK("test"_sv.find("est", 0) == 1);

    CHECK("test"_sv.find("x", 0) == npos);
    CHECK("test"_sv.find("foo", 0) == npos);

    CHECK("test"_sv.find("xxxxx", 0) == npos);
    CHECK("test"_sv.find("testt", 0) == npos);
    CHECK("test"_sv.find("tex", 0) == npos);
    CHECK("test"_sv.find("foobarbaz", 0) == npos);

    // rfind
    CHECK("test"_sv.rfind("t"_sv) == 3);
    CHECK("test"_sv.rfind("est"_sv) == 1);

    CHECK("test"_sv.rfind("st"_sv, 12) == 2);
    CHECK("test"_sv.rfind("st"_sv, 12) == 2);

    CHECK("test"_sv.rfind('t') == 3);
    CHECK("test"_sv.rfind('e') == 1);

    CHECK("test"_sv.rfind('s') == 2);
    CHECK("test"_sv.rfind('s', 2) == 2);
    CHECK(""_sv.rfind('s') == npos);
    CHECK("abc"_sv.rfind('s') == npos);

    CHECK("test"_sv.rfind("t", npos, 1) == 3);
    CHECK("test"_sv.rfind("est", npos, 3) == 1);

    CHECK("test"_sv.rfind("x", npos, 1) == npos);
    CHECK("test"_sv.rfind("foo", npos, 3) == npos);

    CHECK("test"_sv.rfind("t", npos) == 3);
    CHECK("test"_sv.rfind("est", npos) == 1);

    CHECK("test"_sv.rfind("x", 0) == npos);
    CHECK("test"_sv.rfind("foo", 0) == npos);

    CHECK("test"_sv.rfind("xxxxx", 0) == npos);
    CHECK("test"_sv.rfind("foobarbaz", 0) == npos);

    // find_first_of
    CHECK("test"_sv.find_first_of("t"_sv) == 0);
    CHECK("test"_sv.find_first_of("est"_sv) == 0);

    CHECK("test"_sv.find_first_of("t"_sv, 1) == 3);
    CHECK("test"_sv.find_first_of("st"_sv, 2) == 2);

    CHECK("test"_sv.find_first_of('t') == 0);
    CHECK("test"_sv.find_first_of('e') == 1);

    CHECK("test"_sv.find_first_of('t', 1) == 3);
    CHECK("test"_sv.find_first_of('s') == 2);

    CHECK("test"_sv.find_first_of("t", 0, 1) == 0);
    CHECK("test"_sv.find_first_of("est", 0, 3) == 0);

    CHECK("test"_sv.find_first_of("x", 0, 1) == npos);
    CHECK("test"_sv.find_first_of("foo", 0, 3) == npos);

    CHECK("test"_sv.find_first_of("t", 1) == 3);
    CHECK("test"_sv.find_first_of("est", 1) == 1);

    CHECK("test"_sv.find_first_of("x", 0) == npos);
    CHECK("test"_sv.find_first_of("foo", 0) == npos);

    CHECK("test"_sv.find_first_of("xxxxx", 0) == npos);
    CHECK("test"_sv.find_first_of("foobarbaz", 0) == npos);

    // find_first_not_of
    CHECK("BCDEF"_sv.find_first_not_of("BCDEF"_sv) == npos);
    CHECK("BCDEF"_sv.find_first_not_of("ABC"_sv) == 2);
    CHECK("BCDEF"_sv.find_first_not_of("ABC"_sv, 4) == 4);
    CHECK("BCDEF"_sv.find_first_not_of("ABC", 4, 3) == 4);
    CHECK("BCDEF"_sv.find_first_not_of('B') == 1);
    CHECK("BCDEF"_sv.find_first_not_of('D', 2) == 3);
    CHECK("G"_sv.find_first_not_of('G') == npos);

    // find_last_of
    CHECK("test"_sv.find_last_of("t"_sv) == 3);
    CHECK("test"_sv.find_last_of("est"_sv) == 3);

    CHECK("test"_sv.find_last_of("t"_sv, 1) == 0);
    CHECK("test"_sv.find_last_of("st"_sv, 2) == 2);

    CHECK("test"_sv.find_last_of('t') == 3);
    CHECK("test"_sv.find_last_of('e') == 1);
    CHECK("test"_sv.find_last_of('s') == 2);

    CHECK("test"_sv.find_last_of("t", 12, 1) == 3);
    CHECK("test"_sv.find_last_of("es", 12, 2) == 2);

    CHECK("test"_sv.find_last_of("x", 0, 1) == npos);
    CHECK("test"_sv.find_last_of("foo", 0, 3) == npos);

    CHECK("test"_sv.find_last_of("t") == 3);
    CHECK("test"_sv.find_last_of("es") == 2);

    CHECK("test"_sv.find_last_of("x") == npos);
    CHECK("test"_sv.find_last_of("foo") == npos);

    CHECK("test"_sv.find_last_of("xxxxx") == npos);
    CHECK("test"_sv.find_last_of("foobarbaz") == npos);

    // find_last_not_of
    CHECK("test"_sv.find_last_not_of("t"_sv) == 2);
    CHECK("test"_sv.find_last_not_of("est"_sv) == npos);
    CHECK("test"_sv.find_last_not_of(etl::string_view{"s"}, 2) == 1);

    CHECK("test"_sv.find_last_not_of('t') == 2);
    CHECK("test"_sv.find_last_not_of('e') == 3);
    CHECK("test"_sv.find_last_not_of('s') == 3);

    CHECK("test"_sv.find_last_not_of("t", npos, 1) == 2);
    CHECK("test"_sv.find_last_not_of("es", npos, 2) == 3);
    CHECK("test"_sv.find_last_not_of("est", npos, 4) == npos);
    CHECK("test"_sv.find_last_not_of("tes", npos, 4) == npos);

    CHECK("test"_sv.find_last_not_of("t") == 2);
    CHECK("test"_sv.find_last_not_of("es") == 3);

    CHECK("test"_sv.find_last_not_of("tes") == npos);
    CHECK("test"_sv.find_last_not_of("est") == npos);

    return true;
}

auto main() -> int
{
    STATIC_CHECK(test());
    return 0;
}
