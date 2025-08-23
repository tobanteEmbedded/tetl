export namespace etl::experimental::freertos {

using etl::experimental::freertos::create_task;
using etl::experimental::freertos::delete_task;
using etl::experimental::freertos::forever;
using etl::experimental::freertos::never;
using etl::experimental::freertos::once;
using etl::experimental::freertos::rtos_task;
using etl::experimental::freertos::start_scheduler;
using etl::experimental::freertos::times;
using etl::experimental::freertos::twice;

namespace this_task {
using etl::experimental::freertos::this_task::sleep_for;
using etl::experimental::freertos::this_task::sleep_until;
using etl::experimental::freertos::this_task::yield;
} // namespace this_task

} // namespace etl::experimental::freertos
