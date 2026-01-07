include(generic_plugin)
create_generic_plugin(FileHasher)

target_sources(FileHasher PRIVATE
    src/Hasher.cpp
    src/RESTManager.cpp
)

target_sources(FileHasher PUBLIC
    include/Hasher.hpp
    include/RESTManager.hpp
    include/VirusTotalResult.hpp
)

target_include_directories(FileHasher PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

find_package(CURL REQUIRED)
target_link_libraries(FileHasher PRIVATE CURL::libcurl)

find_package(nlohmann_json REQUIRED)
target_link_libraries(FileHasher PRIVATE nlohmann_json::nlohmann_json)

file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/APIKey.txt 
     DESTINATION ${CMAKE_CURRENT_BINARY_DIR})