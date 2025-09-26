add_library(windowsLibrary STATIC  
	file_context.c
	pe_utils.c
	heuristics.c
	logs.c)

target_include_directories(windowsLibrary PUBLIC 
	${CMAKE_CURRENT_SOURCE_DIR}/../lib)
