add_library(allLibraries 
	pe_utils.c 
	file_context.c 
	constants.c 
	print_helper.c 
	pattern.c
	heuristics.c)

target_include_directories(allLibraries PRIVATE 
	${CMAKE_CURRENT_SOURCE_DIR}/../include)
