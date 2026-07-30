add_executable(noleax
  main.cpp
  operations.cpp
)

target_link_libraries(noleax
  PRIVATE
    noleax::analyzer
    noleax::cli
    noleax::controller
    noleax::core
)

noleax_set_project_warnings(noleax)
