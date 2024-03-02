// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_MEMORY_ALLOCATOR_TRAITS_HPP
#define TETL_MEMORY_ALLOCATOR_TRAITS_HPP

namespace etl {

template <typename Alloc>
struct allocator_traits {
    using allocator_type = Alloc;
    using value_type     = typename Alloc::value_type;
    using size_type      = typename Alloc::size_type;
    using pointer        = typename Alloc::pointer;

    [[nodiscard]] static constexpr auto allocate(Alloc& a, size_type n) { return a.allocate(n); }
    static constexpr void deallocate(Alloc& a, pointer p, size_type n) { a.deallocate(p, n); }
};

} // namespace etl

#endif // TETL_MEMORY_ALLOCATOR_TRAITS_HPP
