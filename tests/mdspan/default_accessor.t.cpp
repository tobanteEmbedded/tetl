// SPDX-License-Identifier: BSL-1.0

#include <etl/mdspan.hpp>

#include <etl/array.hpp>
#include <etl/concepts.hpp>
#include <etl/type_traits.hpp>

#include "testing/testing.hpp"

template <typename ElementType>
static constexpr auto test(etl::array<ElementType, 2> elements) -> bool
{
    using accessor_type       = etl::default_accessor<ElementType>;
    using const_accessor_type = etl::default_accessor<ElementType const>;

    CHECK_SAME_TYPE(typename accessor_type::offset_policy, accessor_type);
    CHECK_SAME_TYPE(typename accessor_type::element_type, ElementType);
    CHECK_SAME_TYPE(typename accessor_type::reference, ElementType&);
    CHECK_SAME_TYPE(typename accessor_type::data_handle_type, ElementType*);

    CHECK_SAME_TYPE(typename const_accessor_type::offset_policy, const_accessor_type);
    CHECK_SAME_TYPE(typename const_accessor_type::element_type, ElementType const);
    CHECK_SAME_TYPE(typename const_accessor_type::reference, ElementType const&);
    CHECK_SAME_TYPE(typename const_accessor_type::data_handle_type, ElementType const*);

    CHECK(etl::is_nothrow_default_constructible_v<accessor_type>);
    CHECK(etl::is_nothrow_move_constructible_v<accessor_type>);
    CHECK(etl::is_nothrow_move_assignable_v<accessor_type>);
    CHECK(etl::is_nothrow_swappable_v<accessor_type>);
    CHECK(etl::is_trivially_copyable_v<accessor_type>);
    CHECK(etl::is_empty_v<accessor_type>);

    auto const a = accessor_type{};
    CHECK_SAME_TYPE(decltype(a.access(elements.data(), 0)), ElementType&);
    CHECK_SAME_TYPE(decltype(a.offset(elements.data(), 0)), ElementType*);
    CHECK(a.access(elements.data(), 0) == elements[0]);
    CHECK(a.access(elements.data(), 1) == elements[1]);
    CHECK(a.offset(elements.data(), 0) == etl::next(elements.data(), 0));
    CHECK(a.offset(elements.data(), 1) == etl::next(elements.data(), 1));

    auto const ca = const_accessor_type{a};
    CHECK_SAME_TYPE(decltype(ca.access(elements.data(), 0)), ElementType const&);
    CHECK_SAME_TYPE(decltype(ca.offset(elements.data(), 0)), ElementType const*);
    CHECK(ca.access(elements.data(), 0) == elements[0]);
    CHECK(ca.access(elements.data(), 1) == elements[1]);
    CHECK(ca.offset(elements.data(), 0) == etl::next(elements.data(), 0));
    CHECK(ca.offset(elements.data(), 1) == etl::next(elements.data(), 1));

    return true;
}

static constexpr auto test_all() -> bool
{
    CHECK(test<signed char>({0, 1}));
    CHECK(test<signed short>({0, 1}));
    CHECK(test<signed int>({0, 1}));
    CHECK(test<signed long>({0, 1}));
    CHECK(test<signed long long>({0, 1}));

    CHECK(test<unsigned char>({0, 1}));
    CHECK(test<unsigned short>({0, 1}));
    CHECK(test<unsigned int>({0, 1}));
    CHECK(test<unsigned long>({0, 1}));
    CHECK(test<unsigned long long>({0, 1}));

    CHECK(test<char>({'a', 'b'}));
    CHECK(test<wchar_t>({'a', 'b'}));
    CHECK(test<char8_t>({'a', 'b'}));
    CHECK(test<char16_t>({'a', 'b'}));
    CHECK(test<char32_t>({'a', 'b'}));

    CHECK(test<float>({0.0F, 1.0F}));
    CHECK(test<double>({0.0, 1.0}));
    CHECK(test<long double>({0.0L, 1.0L}));

    return true;
}

auto main() -> int
{
    STATIC_CHECK(test_all());
    return 0;
}
