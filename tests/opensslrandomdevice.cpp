#include "../util/opensslrandomdevice.h"

#include <c++utilities/tests/testutils.h>

#include <cppunit/TestFixture.h>
#include <cppunit/extensions/HelperMacros.h>

#include <random>

using namespace std;
using namespace Util;
using namespace TestUtilities::Literals;

using namespace CPPUNIT_NS;

/*!
 * \brief The OpenSslRandomDeviceTests class tests the Util::OpenSslRandomDevice class.
 */
class OpenSslRandomDeviceTests : public TestFixture {
    CPPUNIT_TEST_SUITE(OpenSslRandomDeviceTests);
    CPPUNIT_TEST(testUsageWithStandardClasses);
    CPPUNIT_TEST_SUITE_END();

public:
    void setUp();
    void tearDown();

    void testUsageWithStandardClasses();
};

CPPUNIT_TEST_SUITE_REGISTRATION(OpenSslRandomDeviceTests);

void OpenSslRandomDeviceTests::setUp()
{
}

void OpenSslRandomDeviceTests::tearDown()
{
}

/*!
 * \brief Tests using the OpenSslRandomDevice with std::uniform_int_distribution.
 */
void OpenSslRandomDeviceTests::testUsageWithStandardClasses()
{
    uniform_int_distribution<> dist(1, 10);
    const Util::OpenSslRandomDevice random;
    const auto val = dist(random);
    CPPUNIT_ASSERT_GREATEREQUAL(1, val);
    CPPUNIT_ASSERT_LESSEQUAL(10, val);
}
