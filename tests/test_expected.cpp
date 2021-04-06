#include "etl/expected.hpp"
#include "etl/warning.hpp"

#include "catch2/catch_template_test_macros.hpp"

TEST_CASE("expected: unexpect_t", "[expected]")
{
  etl::ignore_unused(etl::unexpect);
  STATIC_REQUIRE(etl::is_default_constructible_v<etl::unexpect_t>);
}