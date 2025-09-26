add_library(allLibraries 
	print_helper.c 
)

target_include_directories(allLibraries PUBLIC 
	${CMAKE_CURRENT_SOURCE_DIR}/../include)
