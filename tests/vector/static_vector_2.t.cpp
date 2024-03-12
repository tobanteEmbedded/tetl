// SPDX-License-Identifier: BSL-1.0

#include <etl/vector.hpp>

#include <etl/algorithm.hpp>
#include <etl/cstdint.hpp>
#include <etl/numeric.hpp>
#include <etl/type_traits.hpp>
#include <etl/utility.hpp>

#include "testing/testing.hpp"

using etl::static_vector;

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
        assert(vec.empty());
        assert(etl::rbegin(vec) == etl::rend(vec));
        assert(etl::crbegin(vec) == etl::crend(vec));
        assert(rbegin(as_const(vec)) == rend(as_const(vec)));

        vec.push_back(T{2});
        assert(*etl::rbegin(vec) == T{2});
        assert(!(etl::rbegin(vec) == etl::rend(vec)));
        assert(!(etl::crbegin(vec) == etl::crend(vec)));
        assert(!(rbegin(as_const(vec)) == rend(as_const(vec))));

        vec.push_back(T{3});
        assert(*etl::rbegin(vec) == T{3});
    }

    {
        etl::static_vector<Vertex<T>, 0> zero{};
        assert(zero.empty());
        assert(zero.size() == 0);
        assert(zero.capacity() == 0);
        assert(zero.data() == nullptr);
        assert(zero.full());
    }

    {
        etl::static_vector<Vertex<T>, 16> lhs{};
        assert(lhs.empty());
        etl::static_vector<Vertex<T>, 16> rhs{};
        assert(rhs.empty());

        assert(etl::begin(lhs) == etl::end(lhs));
        assert(etl::cbegin(lhs) == etl::cend(lhs));
        assert(etl::begin(etl::as_const(lhs)) == etl::end(etl::as_const(lhs)));

        assert(lhs == rhs);
        assert(rhs == lhs);
        assert(!(lhs != rhs));
        assert(!(rhs != lhs));
    }

    {
        etl::static_vector<Vertex<T>, 16> lhs{};
        assert(lhs.empty());
        etl::static_vector<Vertex<T>, 16> rhs{};
        assert(rhs.empty());

        rhs.emplace_back(T(1.20F), T(1.00F), T(1.43F));
        assert(!(rhs.empty()));
        assert(!(rhs == lhs));
        assert(rhs.size() == 1);

        lhs.emplace_back(T(1.20F), T(1.00F), T(1.43F));
        assert(!(lhs.empty()));
        assert(rhs == lhs);
        assert(lhs.size() == 1);
    }

    {
        etl::static_vector<Vertex<T>, 3> vec{};
        vec.emplace(vec.end(), T(1.20F), T(1.00F), T(1.43F));
        assert(!(vec.empty()));
        assert(vec.size() == 1);
    }

    {
        etl::static_vector<Vertex<T>, 3> original{};
        auto vertex = Vertex{T(1), T(2), T(3)};
        original.push_back(vertex);
        assert(original.size() == 1);
        assert(original.front() == vertex);
        assert(original.back() == vertex);
        assert(etl::as_const(original).front() == vertex);
        assert(etl::as_const(original).back() == vertex);

        original.pop_back();
        assert(original.size() == 0);
    }

    {
        auto vec = etl::static_vector<Vertex<T>, 3>{};
        assert(vec.size() == 0);
        auto vertex = Vertex{T(1.20F), T(1.00F), T(1.43F)};
        vec.insert(vec.begin(), vertex);
        vec.insert(vec.begin(), vertex);
        assert(vec.size() == 2);
    }

    {
        auto vec = etl::static_vector<Vertex<T>, 3>{};
        assert(vec.size() == 0);
        vec.insert(vec.begin(), Vertex{T(1.20F), T(1.00F), T(1.43F)});
        vec.insert(vec.begin(), Vertex{T(1.20F), T(1.00F), T(1.43F)});
        assert(vec.size() == 2);
    }

    {
        auto a   = Vertex{T(1), T(1), T(1)};
        auto b   = Vertex{T(2), T(2), T(2)};
        auto vec = etl::static_vector<Vertex<T>, 3>{};
        assert(vec.size() == 0);

        vec.insert(vec.begin(), a);
        vec.insert(vec.begin(), b);
        assert(vec[0] == b);
        assert(etl::as_const(vec)[1] == a);
    }
    return true;
}

static auto test_all_runtime() -> bool
{
    assert(test_runtime<etl::int8_t>());
    assert(test_runtime<etl::int16_t>());
    assert(test_runtime<etl::int32_t>());
    assert(test_runtime<etl::int64_t>());
    assert(test_runtime<etl::uint8_t>());
    assert(test_runtime<etl::uint16_t>());
    assert(test_runtime<etl::uint32_t>());
    assert(test_runtime<etl::uint64_t>());
    assert(test_runtime<float>());
    assert(test_runtime<double>());
    return true;
}

auto main() -> int
{
    assert(test_all_runtime());
    return 0;
}
