// SPDX-License-Identifier: BSL-1.0

#include <etl/vector.hpp>

#include <etl/algorithm.hpp>
#include <etl/cstdint.hpp>
#include <etl/numeric.hpp>
#include <etl/type_traits.hpp>
#include <etl/utility.hpp>

#include "testing/testing.hpp"

namespace {
template <typename T>
struct Vertex {
    constexpr Vertex() = default;

    constexpr Vertex(T xInit, T yInit, T zInit) : x{xInit}, y{yInit}, z{zInit} { }

    T x{};
    T y{};
    T z{};
};

template <typename T>
[[nodiscard]] constexpr auto operator==(Vertex<T> const& lhs, Vertex<T> const& rhs) -> bool
{
    return (lhs.x == rhs.x) and (lhs.y == rhs.y) and (lhs.z == rhs.z);
}

// template <typename T>
// [[nodiscard]] constexpr auto operator!=(
//     Vertex<T> const& lhs, Vertex<T> const& rhs) -> bool
// {
//     return !(lhs == rhs);
// }

} // namespace

template <typename T>
auto test_runtime() -> bool
{
    {
        etl::static_vector<T, 16> vec{};
        CHECK(vec.empty());
        CHECK(etl::rbegin(vec) == etl::rend(vec));
        CHECK(etl::crbegin(vec) == etl::crend(vec));
        CHECK(rbegin(as_const(vec)) == rend(as_const(vec)));

        vec.push_back(T{2});
        CHECK(*etl::rbegin(vec) == T{2});
        CHECK(!(etl::rbegin(vec) == etl::rend(vec)));
        CHECK(!(etl::crbegin(vec) == etl::crend(vec)));
        CHECK(!(rbegin(as_const(vec)) == rend(as_const(vec))));

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
        CHECK(!(lhs != rhs));
        CHECK(!(rhs != lhs));
    }

    {
        etl::static_vector<Vertex<T>, 16> lhs{};
        CHECK(lhs.empty());
        etl::static_vector<Vertex<T>, 16> rhs{};
        CHECK(rhs.empty());

        rhs.emplace_back(T(1.20F), T(1.00F), T(1.43F));
        CHECK(!(rhs.empty()));
        CHECK(!(rhs == lhs));
        CHECK(rhs.size() == 1);

        lhs.emplace_back(T(1.20F), T(1.00F), T(1.43F));
        CHECK(!(lhs.empty()));
        CHECK(rhs == lhs);
        CHECK(lhs.size() == 1);
    }

    {
        etl::static_vector<Vertex<T>, 3> vec{};
        vec.emplace(vec.end(), T(1.20F), T(1.00F), T(1.43F));
        CHECK(!(vec.empty()));
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

static auto test_all_runtime() -> bool
{
    CHECK(test_runtime<etl::int8_t>());
    CHECK(test_runtime<etl::int16_t>());
    CHECK(test_runtime<etl::int32_t>());
    CHECK(test_runtime<etl::int64_t>());
    CHECK(test_runtime<etl::uint8_t>());
    CHECK(test_runtime<etl::uint16_t>());
    CHECK(test_runtime<etl::uint32_t>());
    CHECK(test_runtime<etl::uint64_t>());
    CHECK(test_runtime<float>());
    CHECK(test_runtime<double>());
    return true;
}

auto main() -> int
{
    CHECK(test_all_runtime());
    return 0;
}
