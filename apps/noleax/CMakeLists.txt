add_executable(noleax
  main.cpp
)

target_link_libraries(noleax
  PRIVATE
    noleax::cli
    noleax::controller
    noleax::core
)

noleax_set_project_warnings(noleax)
