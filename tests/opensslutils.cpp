#include "../util/openssl.h"

#include <c++utilities/conversion/stringconversion.h>
#include <c++utilities/tests/testutils.h>

#include <cppunit/TestFixture.h>
#include <cppunit/extensions/HelperMacros.h>

#include <random>

using namespace std;
using namespace Util::OpenSsl;
using namespace CppUtilities;
using namespace CppUtilities::Literals;

using namespace CPPUNIT_NS;

/*!
 * \brief The OpenSslUtilsTests class tests the functions in the Util::OpenSsl namespace.
 */
class OpenSslUtilsTests : public TestFixture {
    CPPUNIT_TEST_SUITE(OpenSslUtilsTests);
    CPPUNIT_TEST(testComputeSha256Sum);
    CPPUNIT_TEST(testGenerateRandomNumber);
    CPPUNIT_TEST_SUITE_END();

public:
    void setUp() override;
    void tearDown() override;

    void testComputeSha256Sum();
    void testGenerateRandomNumber();
};

CPPUNIT_TEST_SUITE_REGISTRATION(OpenSslUtilsTests);

void OpenSslUtilsTests::setUp()
{
}

void OpenSslUtilsTests::tearDown()
{
}

void OpenSslUtilsTests::testComputeSha256Sum()
{
    const char someString[] = "hello world";
    Sha256Sum sum = computeSha256Sum(reinterpret_cast<unsigned const char *>(someString), sizeof(someString));
    string sumAsHex;
    sumAsHex.reserve(64);
    for (unsigned char hashNumber : sum.data) {
        const string digits = numberToString(hashNumber, 16);
        sumAsHex.push_back(digits.size() < 2 ? '0' : digits.front());
        sumAsHex.push_back(digits.back());
    }
    CPPUNIT_ASSERT_EQUAL("430646847E70344C09F58739E99D5BC96EAC8D5FE7295CF196B986279876BF9B"s, sumAsHex);
    // note that the termination char is hashed as well
}

void OpenSslUtilsTests::testGenerateRandomNumber()
{
    CPPUNIT_ASSERT_EQUAL(static_cast<uint32_t>(0u), generateRandomNumber(0u, 0u));
    CPPUNIT_ASSERT_EQUAL(static_cast<uint32_t>(1u), generateRandomNumber(1u, 1u));
}
