noinst_PROGRAMS +=							\
	testcases/build/cpp_test

testcases_build_cpp_test_CXXFLAGS = ${testcases_inc}
testcases_build_cpp_test_LDADD = testcases/common/libcommon.la
testcases_build_cpp_test_SOURCES = testcases/build/cpp_test.cpp
