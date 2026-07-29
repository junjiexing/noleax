add_library(noleax-agent SHARED
  agent.cpp
)

target_link_libraries(noleax-agent
  PRIVATE
    hoox::hoox
    noleax::core
)

target_compile_definitions(noleax-agent PRIVATE NOLEAX_AGENT_BUILD)
noleax_set_project_warnings(noleax-agent)

set_target_properties(noleax-agent PROPERTIES
  OUTPUT_NAME "noleax-agent"
  PREFIX ""
)
