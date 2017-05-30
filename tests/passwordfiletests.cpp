#include "../io/cryptoexception.h"
#include "../io/entry.h"
#include "../io/passwordfile.h"

#include <c++utilities/tests/testutils.h>

#include <cppunit/TestFixture.h>
#include <cppunit/extensions/HelperMacros.h>

using namespace std;
using namespace Io;
using namespace TestUtilities::Literals;

using namespace CPPUNIT_NS;

/*!
 * \brief The PasswordFileTests class tests the Io::PasswordFile class.
 */
class PasswordFileTests : public TestFixture {
    CPPUNIT_TEST_SUITE(PasswordFileTests);
    CPPUNIT_TEST(testReading);
#ifdef PLATFORM_UNIX
    CPPUNIT_TEST(testWriting);
#endif
    CPPUNIT_TEST_SUITE_END();

public:
    void setUp();
    void tearDown();

    void testReading();
    void testReading(
        const string &testfile1path, const string &testfile1password, const string &testfile2, const string &testfile2password, bool testfile2Mod);
#ifdef PLATFORM_UNIX
    void testWriting();
#endif
};

CPPUNIT_TEST_SUITE_REGISTRATION(PasswordFileTests);

void PasswordFileTests::setUp()
{
}

void PasswordFileTests::tearDown()
{
}

/*!
 * \brief Tests reading the testfiles testfile{1,2}.pwmgr.
 */
void PasswordFileTests::testReading()
{
    testReading(TestUtilities::testFilePath("testfile1.pwmgr"), "123456", TestUtilities::testFilePath("testfile2.pwmgr"), string(), false);
}

void PasswordFileTests::testReading(
    const string &testfile1path, const string &testfile1password, const string &testfile2, const string &testfile2password, bool testfile2Mod)
{
    PasswordFile file;

    // open testfile 1 ...
    file.setPath(testfile1path);
    file.open(true);

    CPPUNIT_ASSERT(file.isEncryptionUsed() == !testfile1password.empty());
    // attempt to decrypt using a wrong password
    file.setPassword(testfile1password + "asdf");
    if (!testfile1password.empty()) {
        CPPUNIT_ASSERT_THROW(file.load(), CryptoException);
    }
    // attempt to decrypt using the correct password
    file.setPassword(testfile1password);
    file.load();
    // test root entry
    const NodeEntry *rootEntry = file.rootEntry();
    CPPUNIT_ASSERT_EQUAL("testfile1"s, rootEntry->label());
    CPPUNIT_ASSERT_EQUAL(4_st, rootEntry->children().size());

    // test testaccount1
    CPPUNIT_ASSERT_EQUAL("testaccount1"s, rootEntry->children()[0]->label());
    CPPUNIT_ASSERT(rootEntry->children()[0]->type() == EntryType::Account);
    CPPUNIT_ASSERT_EQUAL("pin"s, static_cast<AccountEntry *>(rootEntry->children()[0])->fields().at(0).name());
    CPPUNIT_ASSERT_EQUAL("123456"s, static_cast<AccountEntry *>(rootEntry->children()[0])->fields().at(0).value());
    CPPUNIT_ASSERT(static_cast<AccountEntry *>(rootEntry->children()[0])->fields().at(0).type() == FieldType::Password);
    CPPUNIT_ASSERT(
        static_cast<AccountEntry *>(rootEntry->children()[0])->fields().at(0).tiedAccount() == static_cast<AccountEntry *>(rootEntry->children()[0]));
    CPPUNIT_ASSERT(static_cast<AccountEntry *>(rootEntry->children()[0])->fields().at(1).type() == FieldType::Normal);
    CPPUNIT_ASSERT_THROW(static_cast<AccountEntry *>(rootEntry->children()[0])->fields().at(2), out_of_range);

    // test testaccount2
    CPPUNIT_ASSERT_EQUAL("testaccount2"s, rootEntry->children()[1]->label());
    CPPUNIT_ASSERT(rootEntry->children()[1]->type() == EntryType::Account);
    CPPUNIT_ASSERT(static_cast<AccountEntry *>(rootEntry->children()[1])->fields().empty());

    // test testcategory1
    CPPUNIT_ASSERT_EQUAL("testcategory1"s, rootEntry->children()[2]->label());
    CPPUNIT_ASSERT(rootEntry->children()[2]->type() == EntryType::Node);
    const NodeEntry *category = static_cast<NodeEntry *>(rootEntry->children()[2]);
    CPPUNIT_ASSERT(category->children().size() == 3);
    CPPUNIT_ASSERT(category->children()[2]->type() == EntryType::Node);
    CPPUNIT_ASSERT(static_cast<NodeEntry *>(category->children()[2])->children().size() == 2);

    // test testaccount3
    CPPUNIT_ASSERT_EQUAL("testaccount3"s, rootEntry->children()[3]->label());

    // open testfile 2
    file.setPath(testfile2);
    file.open(true);

    CPPUNIT_ASSERT(file.isEncryptionUsed() == !testfile2password.empty());
    file.setPassword(testfile2password);
    file.load();
    rootEntry = file.rootEntry();
    if (testfile2Mod) {
        CPPUNIT_ASSERT(rootEntry->label() == "testfile2 - modified");
        CPPUNIT_ASSERT(rootEntry->children().size() == 2);
        CPPUNIT_ASSERT(rootEntry->children()[1]->label() == "newAccount");
    } else {
        CPPUNIT_ASSERT(rootEntry->label() == "testfile2");
        CPPUNIT_ASSERT(rootEntry->children().size() == 1);
    }
}

#ifdef PLATFORM_UNIX
/*!
 * \brief Tests writing and reading.
 */
void PasswordFileTests::testWriting()
{
    string testfile1 = TestUtilities::workingCopyPath("testfile1.pwmgr");
    string testfile2 = TestUtilities::workingCopyPath("testfile2.pwmgr");
    PasswordFile file;

    // resave testfile 1
    file.setPath(testfile1);
    file.open(false);
    file.setPassword("123456");
    file.load();
    file.doBackup();
    file.save(false, true);

    // resave testfile 2
    file.setPath(testfile2);
    file.open(false);
    file.load();
    file.rootEntry()->setLabel("testfile2 - modified");
    new AccountEntry("newAccount", file.rootEntry());
    file.setPassword("654321");
    file.doBackup();
    file.save(true, false);

    // check results using the reading test
    testReading(testfile1, string(), testfile2, "654321", true);

    // check backup files
    testReading(testfile1 + ".backup", "123456", testfile2 + ".backup", string(), false);
}
#endif
