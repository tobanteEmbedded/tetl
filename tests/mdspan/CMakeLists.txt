project(mdspan)

tetl_add_test(${PROJECT_NAME} default_accessor)
tetl_add_test(${PROJECT_NAME} extents)
tetl_add_test(${PROJECT_NAME} layout_left)
tetl_add_test(${PROJECT_NAME} layout_right)
tetl_add_test(${PROJECT_NAME} layout_stride)
tetl_add_test(${PROJECT_NAME} mdspan.access)
tetl_add_test(${PROJECT_NAME} mdspan.construct)
tetl_add_test(${PROJECT_NAME} submdspan)
