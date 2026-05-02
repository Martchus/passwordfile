#include "../util/openssl.h"

#include <c++utilities/chrono/datetime.h>
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
    CPPUNIT_TEST(testComputeTOTP);
    CPPUNIT_TEST_SUITE_END();

public:
    void setUp() override;
    void tearDown() override;

    void testComputeSha256Sum();
    void testGenerateRandomNumber();
    void testComputeTOTP();
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
        const string digits = numberToString(hashNumber, static_cast<unsigned char>(16));
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

void OpenSslUtilsTests::testComputeTOTP()
{
    const auto urlDigits6Period30 = "otpauth://totp/foo%20bar?secret=ABCDABCDABCDABCD&period=30&digits=6&issuer=foo%20bar";
    const auto urlDigits8Period15 = "otpauth://totp/foo%20bar?secret=ABCDABCDABCDABCD&period=15&digits=8&issuer=foo%20bar";
    const auto urlSha256Digits8 = "otpauth://totp/foo%20bar?secret=ABCDABCDABCDABCD&period=30&digits=8&algorithm=SHA256";
    const auto urlSha512Digits10 = "otpauth://totp/foo%20bar?secret=ABCDABCDABCDABCD&period=30&digits=10&algorithm=SHA512";

    const auto time = DateTime::fromDateAndTime(2026, 5, 2, 10, 52, 30);
    CPPUNIT_ASSERT_EQUAL("757702"s, computeTOTP(urlDigits6Period30, time));
    CPPUNIT_ASSERT_EQUAL("41448963"s, computeTOTP(urlDigits8Period15, time));
    CPPUNIT_ASSERT_EQUAL("10222808"s, computeTOTP(urlSha256Digits8, time));
    CPPUNIT_ASSERT_EQUAL("0340892126"s, computeTOTP(urlSha512Digits10, time));
}
