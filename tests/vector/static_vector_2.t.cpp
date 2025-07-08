// SPDX-License-Identifier: BSL-1.0

#include "testing/testing.hpp"

#if defined(TETL_ENABLE_CXX_MODULES)
import etl.algorithm;
import etl.array;
import etl.cstddef;
import etl.iterator;
import etl.numeric;
import etl.type_traits;
import etl.utility;
import etl.vector;
#else
    #include <etl/algorithm.hpp>
    #include <etl/array.hpp>
    #include <etl/cstddef.hpp>
    #include <etl/iterator.hpp>
    #include <etl/numeric.hpp>
    #include <etl/type_traits.hpp>
    #include <etl/utility.hpp>
    #include <etl/vector.hpp>
#endif

namespace {
template <typename T>
struct Vertex {
    constexpr Vertex() = default;

    constexpr Vertex(T xInit, T yInit, T zInit)
        : x{xInit}
        , y{yInit}
        , z{zInit}
    {
    }

    friend constexpr auto operator==(Vertex const& lhs, Vertex const& rhs) -> bool = default;

    T x{};
    T y{};
    T z{};
};

} // namespace

template <typename T>
static auto test() -> bool
{
    {
        etl::static_vector<T, 16> vec{};
        CHECK(vec.empty());
        CHECK(etl::rbegin(vec) == etl::rend(vec));
        CHECK(etl::crbegin(vec) == etl::crend(vec));
        CHECK(rbegin(as_const(vec)) == rend(as_const(vec)));

        vec.push_back(T{2});
        CHECK(*etl::rbegin(vec) == T{2});
        CHECK_FALSE(etl::rbegin(vec) == etl::rend(vec));
        CHECK_FALSE(etl::crbegin(vec) == etl::crend(vec));
        CHECK_FALSE(rbegin(as_const(vec)) == rend(as_const(vec)));

        vec.push_back(T{3});
        CHECK(*etl::rbegin(vec) == T{3});
    }

    {
        etl::static_vector<Vertex<T>, 0> zero{};
        CHECK(zero.empty());
        CHECK(zero.size() == 0);
        CHECK(zero.capacity() == 0);
        CHECK(zero.data() == nullptr);
        CHECK(zero.full());
    }

    {
        etl::static_vector<Vertex<T>, 16> lhs{};
        CHECK(lhs.empty());
        etl::static_vector<Vertex<T>, 16> rhs{};
        CHECK(rhs.empty());

        CHECK(etl::begin(lhs) == etl::end(lhs));
        CHECK(etl::cbegin(lhs) == etl::cend(lhs));
        CHECK(etl::begin(etl::as_const(lhs)) == etl::end(etl::as_const(lhs)));

        CHECK(lhs == rhs);
        CHECK(rhs == lhs);
        CHECK_FALSE(lhs != rhs);
        CHECK_FALSE(rhs != lhs);
    }

    {
        etl::static_vector<Vertex<T>, 16> lhs{};
        CHECK(lhs.empty());
        etl::static_vector<Vertex<T>, 16> rhs{};
        CHECK(rhs.empty());

        rhs.emplace_back(T(1.20F), T(1.00F), T(1.43F));
        CHECK_FALSE(rhs.empty());
        CHECK_FALSE(rhs == lhs);
        CHECK(rhs.size() == 1);

        lhs.emplace_back(T(1.20F), T(1.00F), T(1.43F));
        CHECK_FALSE(lhs.empty());
        CHECK(rhs == lhs);
        CHECK(lhs.size() == 1);
    }

    {
        etl::static_vector<Vertex<T>, 3> vec{};
        vec.emplace(vec.end(), T(1.20F), T(1.00F), T(1.43F));
        CHECK_FALSE(vec.empty());
        CHECK(vec.size() == 1);
    }

    {
        etl::static_vector<Vertex<T>, 3> original{};
        auto vertex = Vertex{T(1), T(2), T(3)};
        original.push_back(vertex);
        CHECK(original.size() == 1);
        CHECK(original.front() == vertex);
        CHECK(original.back() == vertex);
        CHECK(etl::as_const(original).front() == vertex);
        CHECK(etl::as_const(original).back() == vertex);

        original.pop_back();
        CHECK(original.size() == 0);
    }

    {
        auto vec = etl::static_vector<Vertex<T>, 3>{};
        CHECK(vec.size() == 0);
        auto vertex = Vertex{T(1.20F), T(1.00F), T(1.43F)};
        vec.insert(vec.begin(), vertex);
        vec.insert(vec.begin(), vertex);
        CHECK(vec.size() == 2);
    }

    {
        auto vec = etl::static_vector<Vertex<T>, 3>{};
        CHECK(vec.size() == 0);
        vec.insert(vec.begin(), Vertex{T(1.20F), T(1.00F), T(1.43F)});
        vec.insert(vec.begin(), Vertex{T(1.20F), T(1.00F), T(1.43F)});
        CHECK(vec.size() == 2);
    }

    {
        auto a   = Vertex{T(1), T(1), T(1)};
        auto b   = Vertex{T(2), T(2), T(2)};
        auto vec = etl::static_vector<Vertex<T>, 3>{};
        CHECK(vec.size() == 0);

        vec.insert(vec.begin(), a);
        vec.insert(vec.begin(), b);
        CHECK(vec[0] == b);
        CHECK(etl::as_const(vec)[1] == a);
    }
    return true;
}

static auto test_all() -> bool
{
    CHECK(test<signed char>());
    CHECK(test<signed short>());
    CHECK(test<signed int>());
    CHECK(test<signed long>());

    CHECK(test<unsigned char>());
    CHECK(test<unsigned short>());
    CHECK(test<unsigned int>());
    CHECK(test<unsigned long>());

    CHECK(test<char>());
    CHECK(test<char8_t>());

    CHECK(test<float>());
    CHECK(test<double>());

// Overflows .text section in debug builds
#if not defined(__AVR__)
    CHECK(test<signed long long>());
    CHECK(test<unsigned long long>());
    CHECK(test<char16_t>());
    CHECK(test<char32_t>());
    CHECK(test<wchar_t>());
    CHECK(test<long double>());
#endif

    return true;
}

auto main() -> int
{
    CHECK(test_all());
    return 0;
}
