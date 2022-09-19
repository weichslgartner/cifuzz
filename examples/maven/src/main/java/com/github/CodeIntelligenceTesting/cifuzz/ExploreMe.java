package com.github.CodeIntelligenceTesting.cifuzz;

import com.code_intelligence.jazzer.api.FuzzerSecurityIssueMedium;

public class ExploreMe {
    // Function with multiple paths that can be discovered by a fuzzer.
    public static void exploreMe(int a, int b, String c) {
        System.out.printf("a: %d, b: %d, c: %s\n", a, b, c);

        if (a >= 20000) {
            System.out.println("branch 1");

            if (b >= 2000000) {
                System.out.println("branch 2");

                if (b - a < 100000) {
                    System.out.println("branch 3");

                    if (c.equals("FUZZING")) {
                        System.out.println("branch 4");
                        throw new FuzzerSecurityIssueMedium("branch 4 has been reached");
                    }
                }
            }
        } else {
            System.out.println("this is the default path");
        }
        System.out.println("---------");
    }
}
