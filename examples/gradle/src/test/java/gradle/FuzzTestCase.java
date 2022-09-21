package gradle;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.junit.FuzzTest;

public class FuzzTestCase {
    @FuzzTest
    void myFuzzTest(FuzzedDataProvider data) {
        int a = data.consumeInt();
        int b = data.consumeInt();
        String c = data.consumeRemainingAsString();

        ExploreMe.exploreMe(a, b, c);
    }
}
