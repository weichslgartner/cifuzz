CXXFLAGS += -std=c++11

clean:
	rm -f *.o *.a *.so a.out

libexplore.so: src/explore/explore_me.cpp src/explore/explore_me.h
	${CXX} ${CXXFLAGS} -shared -fpic -o libexplore.so $<

my_fuzz_test: libexplore.so
	@echo "Building $@"
	# The FUZZ_TEST_CFLAGS and FUZZ_TEST_LDFLAGS environment variables
	# are set by cifuzz when it executes the build command. Those must
	# be passed to the compiler and linker (compiling and linking is
	# done in a single invocation here, so we pass both to $CXX here).
	${CXX} ${CXXFLAGS} ${FUZZ_TEST_CFLAGS} ${FUZZ_TEST_LDFLAGS} -o $@ $@.cpp -Wl,-rpath '-Wl,$$ORIGIN' -L. -lexplore

crashing_fuzz_test.o: src/coverage/crashing_fuzz_test.cpp
	${CXX} ${CXXFLAGS} ${FUZZ_TEST_CFLAGS} -c $<

crashing_fuzz_test: crashing_fuzz_test.o
	${CXX} -o $@ crashing_fuzz_test.o ${LDFLAGS} ${FUZZ_TEST_LDFLAGS}
