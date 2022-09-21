package com.github.CodeIntelligenceTesting.cifuzz;

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

                    // Create reflective call
                    if (c.startsWith("@")) {
                        System.out.println("branch 4");
                        String className = c.substring(1);
                        try {
                            Class.forName(className);
                        } catch (ClassNotFoundException ignored) {
                        }
                    }
                }
            }
        } else {
            System.out.println("this is the default path");
        }
        System.out.println("---------");
    }
}
