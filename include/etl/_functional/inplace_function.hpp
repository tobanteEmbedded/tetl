// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_FUNCTIONAL_INPLACE_FUNCTION_HPP
#define TETL_FUNCTIONAL_INPLACE_FUNCTION_HPP

#include <etl/_cstddef/nullptr_t.hpp>
#include <etl/_cstddef/size_t.hpp>
#include <etl/_exception/exception.hpp>
#include <etl/_exception/raise.hpp>
#include <etl/_memory/addressof.hpp>
#include <etl/_new/operator.hpp>
#include <etl/_type_traits/aligned_storage.hpp>
#include <etl/_type_traits/bool_constant.hpp>
#include <etl/_type_traits/is_copy_constructible.hpp>
#include <etl/_type_traits/is_invocable_r.hpp>
#include <etl/_utility/exchange.hpp>
#include <etl/_utility/forward.hpp>
#include <etl/_utility/swap.hpp>

namespace etl {

struct bad_function_call : exception {
    constexpr bad_function_call() = default;

    constexpr explicit bad_function_call(char const* what)
        : exception{what}
    {
    }
};

namespace detail {

template <typename T>
struct wrapper {
    using type = T;
};

template <typename R, typename... Args>
struct inplace_func_vtable {
    using storage_ptr_t = void*;

    using invoke_ptr_t     = R (*)(storage_ptr_t, Args&&...);
    using process_ptr_t    = void (*)(storage_ptr_t, storage_ptr_t);
    using destructor_ptr_t = void (*)(storage_ptr_t);

    invoke_ptr_t const invoke_ptr;
    process_ptr_t const copy_ptr;
    process_ptr_t const relocate_ptr;
    destructor_ptr_t const destructor_ptr;

    explicit constexpr inplace_func_vtable()
        : invoke_ptr{[](storage_ptr_t /*p*/, Args&&... /*args*/) -> R {
            etl::raise<etl::bad_function_call>("empty inplace_func_vtable");
        }}
        , copy_ptr{[](storage_ptr_t /*p*/, storage_ptr_t /*p*/) -> void {}}
        , relocate_ptr{[](storage_ptr_t /*p*/, storage_ptr_t /*p*/) -> void {}}
        , destructor_ptr{[](storage_ptr_t /*p*/) -> void {}}
    {
    }

    template <typename C>
    explicit constexpr inplace_func_vtable(wrapper<C> /*ignore*/)
        : invoke_ptr{[](storage_ptr_t storagePtr, Args&&... args) -> R {
            return (*static_cast<C*>(storagePtr))(static_cast<Args&&>(args)...);
        }}
        , copy_ptr{[](storage_ptr_t dstPtr, storage_ptr_t srcPtr) -> void {
            ::new (dstPtr) C{(*static_cast<C*>(srcPtr))};
        }}
        , relocate_ptr{[](storage_ptr_t dstPtr, storage_ptr_t srcPtr) -> void {
            ::new (dstPtr) C{etl::move(*static_cast<C*>(srcPtr))};
            static_cast<C*>(srcPtr)->~C();
        }}
        , destructor_ptr{[](storage_ptr_t srcPtr) -> void { static_cast<C*>(srcPtr)->~C(); }}
    {
    }

    inplace_func_vtable(inplace_func_vtable const&) = delete;
    inplace_func_vtable(inplace_func_vtable&&)      = delete;

    auto operator=(inplace_func_vtable const&) -> inplace_func_vtable& = delete;
    auto operator=(inplace_func_vtable&&) -> inplace_func_vtable&      = delete;

    ~inplace_func_vtable() = default;
};

template <typename R, typename... Args>
inline constexpr auto empty_vtable = inplace_func_vtable<R, Args...>{};

template <size_t DstCap, size_t DstAlign, size_t SrcCap, size_t SrcAlign>
struct is_valid_inplace_destination : etl::true_type {
    static_assert(DstCap >= SrcCap);
    static_assert(DstAlign % SrcAlign == 0);
};

} // namespace detail

template <typename Signature, size_t Capacity = sizeof(void*), size_t Alignment = alignof(aligned_storage_t<Capacity>)>
struct inplace_function;

namespace detail {
template <typename>
struct is_inplace_function : false_type { };

template <typename Sig, size_t Cap, size_t Align>
struct is_inplace_function<inplace_function<Sig, Cap, Align>> : etl::true_type { };
} // namespace detail

template <typename R, typename... Args, size_t Capacity, size_t Alignment>
struct inplace_function<R(Args...), Capacity, Alignment> {
private:
    using storage_t    = aligned_storage_t<Capacity, Alignment>;
    using vtable_t     = detail::inplace_func_vtable<R, Args...>;
    using vtable_ptr_t = vtable_t const*;

    template <typename, size_t, size_t>
    friend struct inplace_function;

public:
    using capacity  = integral_constant<size_t, Capacity>;
    using alignment = integral_constant<size_t, Alignment>;

    /// \brief Creates an empty function.
    inplace_function() noexcept
        : _vtable{etl::addressof(detail::empty_vtable<R, Args...>)}
    {
    }

    template <typename T, typename C = decay_t<T>>
        requires(!detail::is_inplace_function<C>::value && is_invocable_r_v<R, C&, Args...>)
    inplace_function(T&& closure)
    {
        static_assert(is_copy_constructible_v<C>, "inplace_function cannot be constructed from non-copyable type");
        static_assert(
            sizeof(C) <= Capacity,
            "inplace_function cannot be constructed from object with this (large) size"
        );
        static_assert(
            Alignment % alignof(C) == 0,
            "inplace_function cannot be constructed from object with this (large) alignment"
        );

        static constexpr vtable_t const vt{detail::wrapper<C>{}};
        _vtable = etl::addressof(vt);

        ::new (etl::addressof(_storage)) C{etl::forward<T>(closure)};
    }

    template <size_t Cap, size_t Align>
    inplace_function(inplace_function<R(Args...), Cap, Align> const& other)
        : inplace_function{other._vtable, other._vtable->copy_ptr, etl::addressof(other._storage)}
    {
        static_assert(
            detail::is_valid_inplace_destination<Capacity, Alignment, Cap, Align>::value,
            "conversion not allowed"
        );
    }

    template <size_t Cap, size_t Align>
    inplace_function(inplace_function<R(Args...), Cap, Align>&& other) noexcept
        : inplace_function{other._vtable, other._vtable->relocate_ptr, etl::addressof(other._storage)}
    {
        static_assert(
            detail::is_valid_inplace_destination<Capacity, Alignment, Cap, Align>::value,
            "conversion not allowed"
        );
        other._vtable = etl::addressof(detail::empty_vtable<R, Args...>);
    }

    /// \brief Creates an empty function.
    inplace_function(nullptr_t /*ignore*/) noexcept
        : _vtable{etl::addressof(detail::empty_vtable<R, Args...>)}
    {
    }

    inplace_function(inplace_function const& other)
        : _vtable{other._vtable}
    {
        _vtable->copy_ptr(etl::addressof(_storage), etl::addressof(other._storage));
    }

    inplace_function(inplace_function&& other) noexcept
        : _vtable{exchange(other._vtable, etl::addressof(detail::empty_vtable<R, Args...>))}
    {
        _vtable->relocate_ptr(etl::addressof(_storage), etl::addressof(other._storage));
    }

    /// \brief Assigns a new target to etl::inplace_function. Drops the current target. *this is empty
    /// after the call.
    auto operator=(nullptr_t) noexcept -> inplace_function&
    {
        _vtable->destructor_ptr(etl::addressof(_storage));
        _vtable = etl::addressof(detail::empty_vtable<R, Args...>);
        return *this;
    }

    auto operator=(inplace_function other) noexcept -> inplace_function&
    {
        _vtable->destructor_ptr(etl::addressof(_storage));
        _vtable = exchange(other._vtable, etl::addressof(detail::empty_vtable<R, Args...>));
        _vtable->relocate_ptr(etl::addressof(_storage), etl::addressof(other._storage));
        return *this;
    }

    /// \brief Destroys the etl::inplace_function instance.
    /// If the etl::inplace_function is not empty, its target is destroyed also.
    ~inplace_function()
    {
        _vtable->destructor_ptr(etl::addressof(_storage));
    }

    /// \brief Invokes the stored callable function target with the parameters args.
    auto operator()(Args... args) const -> R
    {
        return _vtable->invoke_ptr(etl::addressof(_storage), etl::forward<Args>(args)...);
    }

    /// \brief Checks whether *this stores a callable function target, i.e. is not empty.
    [[nodiscard]] explicit constexpr operator bool() const noexcept
    {
        return _vtable != etl::addressof(detail::empty_vtable<R, Args...>);
    }

    /// \brief Exchanges the stored callable objects of *this and other.
    auto swap(inplace_function& other) noexcept -> void
    {
        auto tmp = storage_t{};
        _vtable->relocate_ptr(etl::addressof(tmp), etl::addressof(_storage));
        other._vtable->relocate_ptr(etl::addressof(_storage), etl::addressof(other._storage));
        _vtable->relocate_ptr(etl::addressof(other._storage), etl::addressof(tmp));
        etl::swap(_vtable, other._vtable);
    }

private:
    inplace_function(
        vtable_ptr_t vtable,
        typename vtable_t::process_ptr_t process,
        typename vtable_t::storage_ptr_t storage
    )
        : _vtable{vtable}
    {
        process(etl::addressof(_storage), storage);
    }

    vtable_ptr_t _vtable;
    storage_t mutable _storage;
};

/// \brief Overloads the etl::swap algorithm for etl::inplace_function.
/// Exchanges the state of lhs with that of rhs. Effectively calls
/// lhs.swap(rhs).
template <typename R, typename... Args, size_t Capacity, size_t Alignment>
auto swap(
    inplace_function<R(Args...), Capacity, Alignment>& lhs,
    inplace_function<R(Args...), Capacity, Alignment>& rhs
) noexcept -> void
{
    lhs.swap(rhs);
}

/// \brief Compares a etl::inplace_function with a null pointer. Empty functions
/// (that is, functions without a callable target) compare equal, non-empty
/// functions compare non-equal.
template <typename R, typename... Args, size_t Capacity, size_t Alignment>
[[nodiscard]] constexpr auto
operator==(inplace_function<R(Args...), Capacity, Alignment> const& f, nullptr_t /*ignore*/) noexcept -> bool
{
    return !static_cast<bool>(f);
}

/// \brief Compares a etl::inplace_function with a null pointer. Empty functions
/// (that is, functions without a callable target) compare equal, non-empty
/// functions compare non-equal.
template <typename R, typename... Args, size_t Capacity, size_t Alignment>
[[nodiscard]] constexpr auto
operator!=(inplace_function<R(Args...), Capacity, Alignment> const& f, nullptr_t /*ignore*/) noexcept -> bool
{
    return static_cast<bool>(f);
}

/// \brief Compares a etl::inplace_function with a null pointer. Empty functions
/// (that is, functions without a callable target) compare equal, non-empty
/// functions compare non-equal.
template <typename R, typename... Args, size_t Capacity, size_t Alignment>
[[nodiscard]] constexpr auto
operator==(nullptr_t /*ignore*/, inplace_function<R(Args...), Capacity, Alignment> const& f) noexcept -> bool
{
    return !static_cast<bool>(f);
}

/// \brief Compares a etl::inplace_function with a null pointer. Empty functions
/// (that is, functions without a callable target) compare equal, non-empty
/// functions compare non-equal.
template <typename R, typename... Args, size_t Capacity, size_t Alignment>
[[nodiscard]] constexpr auto
operator!=(nullptr_t /*ignore*/, inplace_function<R(Args...), Capacity, Alignment> const& f) noexcept -> bool
{
    return static_cast<bool>(f);
}

} // namespace etl

#endif // TETL_FUNCTIONAL_INPLACE_FUNCTION_HPP
