/*
Copyright (c) 2019-2020, Tobias Hienzsch
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

 * Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.
 * Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND ANY
EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
DAMAGE.
*/

#ifndef TAETL_MEMORY_HPP
#define TAETL_MEMORY_HPP

#include "etl/bit.hpp"
#include "etl/cassert.hpp"
#include "etl/cstddef.hpp"
#include "etl/limits.hpp"
#include "etl/type_traits.hpp"
#include "etl/warning.hpp"

#include "etl/detail/sfinae.hpp"

namespace etl
{
/**
 * @brief Obtains the actual address of the object or function arg, even in
 * presence of overloaded operator&.
 */
template <typename T, TAETL_REQUIRES_(etl::is_object_v<T>)>
auto addressof(T& arg) noexcept -> T*
{
  return reinterpret_cast<T*>(
    &const_cast<char&>(reinterpret_cast<const volatile char&>(arg)));
}

/**
 * @brief Obtains the actual address of the object or function arg, even in
 * presence of overloaded operator&.
 */
template <typename T, TAETL_REQUIRES_(!etl::is_object_v<T>)>
auto addressof(T& arg) noexcept -> T*
{
  return &arg;
}

/**
 * @brief Rvalue overload is deleted to prevent taking the address of const
 * rvalues.
 */
template <typename T>
auto addressof(T const&&) = delete;

/**
 * @brief If T is not an array type, calls the destructor of the object pointed
 * to by p, as if by p->~T(). If T is an array type, recursively destroys
 * elements of *p in order, as if by calling etl::destroy(etl::begin(*p),
 * etl::end(*p)).
 */
template <typename T>
constexpr auto destroy_at(T* p) -> void
{
  if constexpr (etl::is_array_v<T>)
  {
    for (auto& elem : *p) { etl::destroy_at(etl::addressof(elem)); }
  }
  else
  {
    p->~T();
  }
}

/**
 * @brief Destroys the objects in the range [first, last).
 */
template <typename ForwardIt>
constexpr auto destroy(ForwardIt first, ForwardIt last) -> void
{
  for (; first != last; ++first) { etl::destroy_at(etl::addressof(*first)); }
}

/**
 * @brief Destroys the n objects in the range starting at first.
 */
template <typename ForwardIt, typename Size>
constexpr auto destroy_n(ForwardIt first, Size n) -> ForwardIt
{
  for (; n > 0; (void)++first, --n) { etl::destroy_at(etl::addressof(*first)); }
  return first;
}

/**
 * @brief The pointer_traits class template provides the standardized way to
 * access certain properties of pointer-like types.
 *
 * @details https://en.cppreference.com/w/cpp/memory/pointer_traits
 */
template <typename Ptr>
struct pointer_traits
{
  using pointer         = Ptr;
  using element_type    = typename Ptr::element_type;
  using difference_type = typename Ptr::difference_type;

  /**
   * @brief Constructs a dereferenceable pointer or pointer-like object ("fancy
   * pointer") to its argument.
   *
   * @details https://en.cppreference.com/w/cpp/memory/pointer_traits/pointer_to
   * @param r  Reference to an object of type element_type&.
   * @returns A pointer to r, of the type pointer_traits::pointer.
   */
  [[nodiscard]] static auto pointer_to(element_type& r) -> pointer
  {
    return Ptr::pointer_to(r);
  }
};

/**
 * @brief The pointer_traits class template provides the standardized way to
 * access certain properties of pointer-like types.
 *
 * @details https://en.cppreference.com/w/cpp/memory/pointer_traits
 */
template <typename T>
struct pointer_traits<T*>
{
  using pointer         = T*;
  using element_type    = T;
  using difference_type = ::etl::ptrdiff_t;
  template <typename U>
  using rebind = U*;

  /**
   * @brief Constructs a dereferenceable pointer or pointer-like object ("fancy
   * pointer") to its argument.
   *
   * @details https://en.cppreference.com/w/cpp/memory/pointer_traits/pointer_to
   * @param r  Reference to an object of type element_type&.
   * @returns A pointer to r, of the type pointer_traits::pointer.
   */
  [[nodiscard]] static auto pointer_to(element_type& r) -> pointer
  {
    return addressof(r);
  }
};

/**
 * @brief allocator_arg_t is an empty class type used to disambiguate the
 * overloads of constructors and member functions of allocator-aware objects.
 */
struct allocator_arg_t
{
  explicit allocator_arg_t() = default;
};

/**
 * @brief allocator_arg is a constant of type allocator_arg_t used to
 * disambiguate, at call site, the overloads of the constructors and member
 * functions of allocator-aware objects.
 */
inline constexpr allocator_arg_t allocator_arg {};

namespace detail
{
template <typename Type, typename Alloc, typename = void>
struct uses_allocator_impl : false_type
{
};

template <typename Type, typename Alloc>
struct uses_allocator_impl<Type, Alloc, void_t<typename Type::allocator_type>>
    : is_convertible<Alloc, typename Type::allocator_type>::type
{
};
}  // namespace detail

/**
 * @brief If T has a member typedef allocator_type which is convertible from
 * Alloc, the member constant value is true. Otherwise value is false.
 */
template <typename Type, typename Alloc>
struct uses_allocator : detail::uses_allocator_impl<Type, Alloc>::type
{
};

/**
 * @brief If T has a member typedef allocator_type which is convertible from
 * Alloc, the member constant value is true. Otherwise value is false.
 */
template <typename Type, typename Alloc>
inline constexpr auto uses_allocator_v = uses_allocator<Type, Alloc>::value;

/**
 * @brief Compressed pointer to specified size. Intended to be used as a drop in
 * replacement for native pointers.
 *
 * @details Uses the base address to calculate an offset, which will be stored
 * internally. If used on micro controllers, the base address should be set to
 * the start of RAM. See your linker script.
 */
template <typename Type, intptr_t BaseAddress = 0,
          typename StorageType = uint16_t>
class small_ptr
{
  public:
  /**
   * @brief Default construct empty small_ptr. May contain garbage.
   */
  small_ptr() = default;

  /**
   * @brief Construct from nullptr.
   */
  small_ptr(nullptr_t null) : value_ {0} { ignore_unused(null); }

  /**
   * @brief Construct from raw pointer.
   */
  small_ptr(Type* ptr) : value_ {compress(ptr)} { }

  /**
   * @brief Returns a raw pointer to Type.
   */
  [[nodiscard]] auto get() noexcept -> Type*
  {
    return reinterpret_cast<Type*>(BaseAddress + value_);
  }

  /**
   * @brief Returns a raw pointer to const Type.
   */
  [[nodiscard]] auto get() const noexcept -> Type const*
  {
    return reinterpret_cast<Type const*>(BaseAddress + value_);
  }

  /**
   * @brief Returns the compressed underlying integer address.
   */
  [[nodiscard]] auto compressed_value() const noexcept -> StorageType
  {
    return value_;
  }

  /**
   * @brief Returns a raw pointer to Type.
   */
  [[nodiscard]] auto operator->() const -> Type* { return get(); }

  /**
   * @brief Dereference pointer to Type&.
   */
  [[nodiscard]] auto operator*() -> Type& { return *get(); }

  /**
   * @brief Dereference pointer to Type const&.
   */
  [[nodiscard]] auto operator*() const -> Type const& { return *get(); }

  /**
   * @brief Pre increment of pointer.
   */
  [[nodiscard]] auto operator++(int) noexcept -> small_ptr
  {
    auto temp = *this;
    auto* ptr = get();
    ++ptr;
    value_ = compress(ptr);
    return temp;
  }

  /**
   * @brief Post increment of pointer.
   */
  [[nodiscard]] auto operator++() noexcept -> small_ptr&
  {
    auto* ptr = get();
    ptr++;
    value_ = compress(ptr);
    return *this;
  }

  /**
   * @brief Pre decrement of pointer.
   */
  [[nodiscard]] auto operator--(int) noexcept -> small_ptr
  {
    auto temp = *this;
    auto* ptr = get();
    --ptr;
    value_ = compress(ptr);
    return temp;
  }

  /**
   * @brief Post decrement of pointer.
   */
  [[nodiscard]] auto operator--() noexcept -> small_ptr&
  {
    auto* ptr = get();
    ptr--;
    value_ = compress(ptr);
    return *this;
  }

  /**
   * @brief Returns distance from this to other.
   */
  [[nodiscard]] auto operator-(small_ptr other) const noexcept -> ptrdiff_t
  {
    return get() - other.get();
  }

  /**
   * @brief Implicit conversion to raw pointer to mutable.
   */
  [[nodiscard]] operator Type*() noexcept { return get(); }

  /**
   * @brief Implicit conversion to raw pointer to const.
   */
  [[nodiscard]] operator Type const *() const noexcept { return get(); }

  private:
  [[nodiscard]] static auto compress(Type* ptr) -> StorageType
  {
    auto const obj = reinterpret_cast<intptr_t>(ptr);
    return StorageType(obj - BaseAddress);
  }

  StorageType value_;
};

namespace detail
{
// Compile time version of log2 that handles 0.
static constexpr auto log2(size_t value) -> size_t
{
  return (value == 0 || value == 1) ? 0 : 1 + log2(value / 2);
}

}  // namespace detail

/**
 * @brief A traits type that is used to handle pointer types and things that are
 * just wrappers for pointers as a uniform entity.
 */
template <typename T>
struct pointer_like_traits;

/**
 * @brief Provide pointer_like_traits for non-cvr pointers.
 */
template <typename T>
struct pointer_like_traits<T*>
{
  static auto get_as_void_pointer(T* p) -> void* { return p; }
  static auto get_from_void_pointer(void* p) -> T*
  {
    return static_cast<T*>(p);
  }

  static constexpr int free_bits = detail::log2(alignof(T));
};

// Provide pointer_like_traits for const things.
template <typename T>
struct pointer_like_traits<const T>
{
  using non_const = pointer_like_traits<T>;

  static auto get_as_void_pointer(const T p) -> const void*
  {
    return non_const::get_as_void_pointer(p);
  }

  // NOLINTNEXTLINE(readability-const-return-type)
  static auto get_from_void_pointer(const void* p) -> const T
  {
    return non_const::get_from_void_pointer(const_cast<void*>(p));
  }
  static constexpr int free_bits = non_const::free_bits;
};

// Provide pointer_like_traits for const pointers.
template <typename T>
struct pointer_like_traits<const T*>
{
  using non_const = pointer_like_traits<T*>;

  static auto get_as_void_pointer(const T* p) -> const void*
  {
    return non_const::get_as_void_pointer(const_cast<T*>(p));
  }
  static auto get_from_void_pointer(const void* p) -> const T*
  {
    return non_const::get_from_void_pointer(const_cast<void*>(p));
  }
  static constexpr int free_bits = non_const::free_bits;
};

// Provide pointer_like_traits for uintptr_t.
template <>
struct pointer_like_traits<uintptr_t>
{
  static auto get_as_void_pointer(uintptr_t p) -> void*
  {
    return reinterpret_cast<void*>(p);
  }
  static auto get_from_void_pointer(void* p) -> uintptr_t
  {
    return reinterpret_cast<uintptr_t>(p);
  }
  // No bits are available!
  static constexpr int free_bits = 0;
};

template <typename PointerT, unsigned IntBits, typename PtrTraits>
struct pointer_int_pair_info
{
  static_assert(PtrTraits::free_bits < numeric_limits<uintptr_t>::digits,
                "cannot use a pointer type that has all bits free");
  static_assert(IntBits <= PtrTraits::free_bits,
                "pointer_int_pair with integer size too large for pointer");
  /// ptr_mask - The bits that come from the pointer.
  static constexpr auto ptr_mask
    = ~(uintptr_t)(((intptr_t)1 << PtrTraits::free_bits) - 1);

  /// The number of low bits that we reserve for other uses; and keep zero.
  static constexpr auto int_shift = (uintptr_t)PtrTraits::free_bits - IntBits;

  /// int_mask - This is the unshifted mask for valid bits of the int type.
  static constexpr auto int_mask = (uintptr_t)(((intptr_t)1 << IntBits) - 1);

  // shifted_int_mask - This is the bits for the integer shifted in place.
  static constexpr auto shifted_int_mask = (uintptr_t)(int_mask << int_shift);

  [[nodiscard]] static auto get_pointer(intptr_t value) -> PointerT
  {
    return PtrTraits::get_from_void_pointer(
      reinterpret_cast<void*>(value & ptr_mask));
  }

  [[nodiscard]] static auto get_int(intptr_t value) -> intptr_t
  {
    return (value >> int_shift) & int_mask;
  }

  [[nodiscard]] static auto update_ptr(intptr_t originalValue, PointerT ptr)
    -> intptr_t
  {
    // Preserve all low bits, just update the pointer.
    auto* voidPtr    = PtrTraits::get_as_void_pointer(ptr);
    auto pointerWord = reinterpret_cast<intptr_t>(voidPtr);
    return pointerWord | (originalValue & ~ptr_mask);
  }

  [[nodiscard]] static auto update_int(intptr_t originalValue, intptr_t integer)
    -> intptr_t
  {
    // Preserve all bits other than the ones we are updating.
    auto const integerWord = static_cast<intptr_t>(integer);
    return (originalValue & ~shifted_int_mask) | integerWord << int_shift;
  }
};

/// pointer_int_pair - This class implements a pair of a pointer and small
/// integer.  It is designed to represent this in the space required by one
/// pointer by bitmangling the integer into the low part of the pointer.  This
/// can only be done for small integers: typically up to 3 bits, but it depends
/// on the number of bits available according to pointer_like_traits for the
/// type.
///
/// Note that pointer_int_pair always puts the IntVal part in the highest bits
/// possible.  For example, pointer_int_pair<void*, 1, bool> will put the bit
/// for the bool into bit #2, not bit #0, which allows the low two bits to be
/// used for something else.  For example, this allows:
///   pointer_int_pair<pointer_int_pair<void*, 1, bool>, 1, bool>
/// ... and the two bools will land in different bits.
template <typename PointerT, unsigned IntBits, typename IntType = unsigned,
          typename PtrTraits = pointer_like_traits<PointerT>,
          typename Info = pointer_int_pair_info<PointerT, IntBits, PtrTraits>>
class pointer_int_pair
{
  public:
  constexpr pointer_int_pair() = default;

  pointer_int_pair(PointerT ptrVal, IntType intVal)
  {
    set_ptr_and_int(ptrVal, intVal);
  }

  explicit pointer_int_pair(PointerT ptrVal) { init_with_ptr(ptrVal); }

  [[nodiscard]] auto get_pointer() const -> PointerT
  {
    return Info::get_pointer(value_);
  }

  [[nodiscard]] auto get_int() const -> IntType
  {
    return (IntType)Info::get_int(value_);
  }

  void set_pointer(PointerT ptrVal)
  {
    value_ = Info::update_ptr(value_, ptrVal);
  }

  void set_int(IntType intVal)
  {
    value_ = Info::update_int(value_, static_cast<intptr_t>(intVal));
  }

  void init_with_ptr(PointerT ptrVal) { value_ = Info::update_ptr(0, ptrVal); }

  void set_ptr_and_int(PointerT ptrVal, IntType intVal)
  {
    value_ = Info::update_int(Info::update_ptr(0, ptrVal),
                              static_cast<intptr_t>(intVal));
  }

  [[nodiscard]] auto get_addr_of_pointer() const -> PointerT const*
  {
    return const_cast<pointer_int_pair*>(this)->get_addr_of_pointer();
  }

  auto get_addr_of_pointer() -> PointerT*
  {
    return reinterpret_cast<PointerT*>(&value_);
  }

  [[nodiscard]] auto get_opaquevalue() const -> void*
  {
    return reinterpret_cast<void*>(value_);
  }

  void set_from_opaque_value(void* val)
  {
    value_ = reinterpret_cast<intptr_t>(val);
  }

  static auto get_from_opaque_value(void* v) -> pointer_int_pair
  {
    pointer_int_pair p;
    p.set_from_opaque_value(v);
    return p;
  }

  // Allow pointer_int_pairs to be created from const void * if and only if the
  // pointer type could be created from a const void *.
  static auto get_from_opaque_value(const void* v) -> pointer_int_pair
  {
    (void)PtrTraits::get_from_void_pointer(v);
    return get_from_opaque_value(const_cast<void*>(v));
  }

  auto operator==(const pointer_int_pair& other) const -> bool
  {
    return value_ == other.value_;
  }

  auto operator!=(const pointer_int_pair& other) const -> bool
  {
    return value_ != other.value_;
  }

  auto operator<(const pointer_int_pair& other) const -> bool
  {
    return value_ < other.value_;
  }
  auto operator>(const pointer_int_pair& other) const -> bool
  {
    return value_ > other.value_;
  }

  auto operator<=(const pointer_int_pair& other) const -> bool
  {
    return value_ <= other.value_;
  }

  auto operator>=(const pointer_int_pair& other) const -> bool
  {
    return value_ >= other.value_;
  }

  private:
  intptr_t value_ = 0;
};

template <typename T>
class default_delete
{
  public:
  constexpr default_delete() noexcept = default;

  template <typename U, TAETL_REQUIRES_((etl::is_convertible_v<U*, T*>))>
  default_delete(default_delete<U> const& /*unused*/) noexcept
  {
  }

  auto operator()(T* ptr) const noexcept -> void { delete ptr; }

  private:
  static_assert(!etl::is_function<T>::value);
  static_assert(sizeof(T));
  static_assert(!etl::is_void<T>::value);
};

template <typename T>
class default_delete<T[]>
{
  public:
  constexpr default_delete() noexcept = default;

  template <typename U,
            TAETL_REQUIRES_((etl::is_convertible_v<U (*)[], T (*)[]>))>
  default_delete(default_delete<U[]> const& /*unused*/) noexcept
  {
  }

  template <typename U,
            TAETL_REQUIRES_(etl::is_convertible_v<U (*)[], T (*)[]>)>
  auto operator()(U* arrayPtr) const noexcept -> void
  {
    delete[] arrayPtr;
  }

  private:
  static_assert(sizeof(T));
  static_assert(!etl::is_void<T>::value);
};

/**
 * @brief Given a pointer ptr to a buffer of size space, returns a pointer
 * aligned by the specified alignment for size number of bytes and decreases
 * space argument by the number of bytes used for alignment. The first aligned
 * address is returned.
 *
 * The function modifies the pointer only if it would be possible to fit the
 * wanted number of bytes aligned by the given alignment into the buffer. If the
 * buffer is too small, the function does nothing and returns nullptr.
 *
 * The behavior is undefined if alignment is not a power of two.
 */
[[nodiscard]] inline auto align(size_t alignment, size_t size, void*& ptr,
                                size_t& space) noexcept -> void*
{
  auto off = static_cast<size_t>(bit_cast<uintptr_t>(ptr) & (alignment - 1));
  if (off != 0) { off = alignment - off; }
  if (space < off || space - off < size) { return nullptr; }

  ptr = static_cast<char*>(ptr) + off;
  space -= off;
  return ptr;
}

}  // namespace etl
#endif  // TAETL_MEMORY_HPP