all: crashing_fuzz_test

clean:
	rm -f *.o *.a *.so a.out

crashing_fuzz_test.o: crashing_fuzz_test.cpp
	${CXX} ${CXXFLAGS} ${FUZZ_TEST_CFLAGS} -c crashing_fuzz_test.cpp

crashing_fuzz_test: crashing_fuzz_test.o
	${CXX} -o crashing_fuzz_test crashing_fuzz_test.o ${LDFLAGS} ${FUZZ_TEST_LDFLAGS}
