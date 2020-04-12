#ifndef TAETL_VECTOR_HPP
#define TAETL_VECTOR_HPP

#include "taetl/definitions.hpp"

namespace taetl
{
template <typename ValueType>
class vector
{
public:
    using value_type = ValueType;

    using size_type       = taetl::size_t;
    using difference_type = taetl::ptrdiff_t;

    using pointer       = ValueType*;
    using const_pointer = const ValueType*;

    using reference       = ValueType&;
    using const_reference = const ValueType&;

    using iterator       = ValueType*;
    using const_iterator = const ValueType*;

public:
    [[nodiscard]] constexpr auto empty() const noexcept -> bool
    {
        return size_ == 0;
    }

    [[nodiscard]] constexpr auto size() const noexcept -> size_type
    {
        return size_;
    }

    [[nodiscard]] constexpr auto max_size() const noexcept -> size_type
    {
        return capacity_;
    }

    [[nodiscard]] constexpr auto capacity() const noexcept -> size_type
    {
        return capacity_;
    }

    [[nodiscard]] constexpr auto data() noexcept -> pointer { return data_; }

    [[nodiscard]] constexpr auto data() const noexcept -> const_pointer
    {
        return data_;
    }

    /**
     * @brief Returns an iterator to the beginning.
     */
    [[nodiscard]] constexpr iterator begin() noexcept { return data_; }

    /**
     * @brief Returns an const iterator to the beginning.
     */
    [[nodiscard]] constexpr const_iterator cbegin() const noexcept { return data_; }

    /**
     * @brief Returns an iterator to the end.
     */
    [[nodiscard]] constexpr iterator end() noexcept { return data_ + size(); }

    /**
     * @brief Returns an const iterator to the end.
     */
    [[nodiscard]] constexpr const_iterator cend() const noexcept { return data_ + size(); }

    /**
     * @brief Accesses the first item.
     */
    [[nodiscard]] constexpr reference front() noexcept { return data_[0]; }

    /**
     * @brief Accesses the last item.
     */
    [[nodiscard]] constexpr reference back() noexcept { return data_[size_ - 1]; }

    /**
     * @brief Adds one element to the back. It fails silently if the Array is
     * full
     */
    constexpr auto push_back( ValueType const& value) noexcept -> void
    {
        if (size_ >= capacity_)
        {
            return;
        }

        data_[size_++] = value;
    }

    /**
     * @brief Decrements the size by 1.
     */
    constexpr void pop_back() noexcept
    {
        if (size_ > 0)
        {
            size_--;
        }
    }

    auto reserve(size_type new_cap) -> void = delete;
    auto shrink_to_fit() -> void            = delete;

protected:
    explicit vector(ValueType* data, size_t size, size_t capacity)
        : data_(data), size_(size), capacity_(capacity)
    {
    }

private:
    ValueType* data_;
    size_t size_;
    size_t const capacity_;
};

namespace make
{
template <typename ValueType, size_t Size>
class vector : public ::taetl::vector<ValueType>
{
public:
    explicit vector() : ::taetl::vector<ValueType> {data_, 0, Size} {}

private:
    ValueType data_[Size];
};
}  // namespace make
}  // namespace taetl
#endif  // TAETL_VECTOR_HPP
