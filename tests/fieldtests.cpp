#include "../io/entry.h"
#include "../io/field.h"

#include "./utils.h"

#include <c++utilities/tests/testutils.h>
using namespace TestUtilities;

#include <cppunit/TestFixture.h>
#include <cppunit/extensions/HelperMacros.h>

using namespace std;
using namespace Io;
using namespace TestUtilities::Literals;

using namespace CPPUNIT_NS;

/*!
 * \brief The FieldTests class tests the Io::Field class.
 */
class FieldTests : public TestFixture {
    CPPUNIT_TEST_SUITE(FieldTests);
    CPPUNIT_TEST(testNewFieldCorrectlyInitialized);
    CPPUNIT_TEST(testMutation);
    CPPUNIT_TEST_SUITE_END();

public:
    void setUp() override;
    void tearDown() override;

    void testNewFieldCorrectlyInitialized();
    void testMutation();
};

CPPUNIT_TEST_SUITE_REGISTRATION(FieldTests);

void FieldTests::setUp()
{
}

void FieldTests::tearDown()
{
}

/*!
 * \brief Tests whether a new field is correctly initialized (default values set).
 */
void FieldTests::testNewFieldCorrectlyInitialized()
{
    AccountEntry account("account");
    const Field emptyField(&account);
    CPPUNIT_ASSERT(emptyField.isEmpty());

    const Field field(&account, "foo", "bar");
    CPPUNIT_ASSERT(!field.isEmpty());
    CPPUNIT_ASSERT_EQUAL(&account, field.tiedAccount());
    CPPUNIT_ASSERT_EQUAL("foo"s, field.name());
    CPPUNIT_ASSERT_EQUAL("bar"s, field.value());
    CPPUNIT_ASSERT_EQUAL(FieldType::Normal, field.type());
}

void FieldTests::testMutation()
{
    AccountEntry account("account");
    Field field(&account, "foo", "bar");
    field.setName("bar");
    field.setValue("foo");
    field.setType(FieldType::Password);
    CPPUNIT_ASSERT_EQUAL("bar"s, field.name());
    CPPUNIT_ASSERT_EQUAL("foo"s, field.value());
    CPPUNIT_ASSERT_EQUAL(FieldType::Password, field.type());
}
