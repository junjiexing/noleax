add_executable(noleax
  main.cpp
)

target_link_libraries(noleax
  PRIVATE
    CLI11::CLI11
    noleax::core
)

noleax_set_project_warnings(noleax)
