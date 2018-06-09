#include "../io/entry.h"

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
 * \brief The EntryTests class tests the Io::Entry class.
 */
class EntryTests : public TestFixture {
    CPPUNIT_TEST_SUITE(EntryTests);
    CPPUNIT_TEST(testNewEntryCorrectlyInitialized);
    CPPUNIT_TEST(testNesting);
    CPPUNIT_TEST(testEntryByPath);
    CPPUNIT_TEST(testUniqueLabels);
    CPPUNIT_TEST_SUITE_END();

public:
    void setUp();
    void tearDown();

    void testNewEntryCorrectlyInitialized();
    void testNesting();
    void testEntryByPath();
    void testUniqueLabels();
};

CPPUNIT_TEST_SUITE_REGISTRATION(EntryTests);

void EntryTests::setUp()
{
}

void EntryTests::tearDown()
{
}

/*!
 * \brief Tests whether a new entry is correctly initialized (basically empty, default values set).
 */
void EntryTests::testNewEntryCorrectlyInitialized()
{
    const NodeEntry nodeEntry;
    CPPUNIT_ASSERT(!nodeEntry.parent());
    CPPUNIT_ASSERT_EQUAL(string(), nodeEntry.label());
    CPPUNIT_ASSERT_EQUAL(0_st, nodeEntry.children().size());
    CPPUNIT_ASSERT_EQUAL(-1, nodeEntry.index());
    CPPUNIT_ASSERT_EQUAL(list<string>{ "" }, nodeEntry.path());
    CPPUNIT_ASSERT(nodeEntry.isExpandedByDefault());
    CPPUNIT_ASSERT_EQUAL(EntryType::Node, nodeEntry.type());

    const AccountEntry accountEntry;
    CPPUNIT_ASSERT(!accountEntry.parent());
    CPPUNIT_ASSERT_EQUAL(string(), nodeEntry.label());
    CPPUNIT_ASSERT_EQUAL(0_st, accountEntry.fields().size());
    CPPUNIT_ASSERT_EQUAL(-1, accountEntry.index());
    CPPUNIT_ASSERT_EQUAL(list<string>{ "" }, accountEntry.path());
    CPPUNIT_ASSERT_EQUAL(EntryType::Account, accountEntry.type());

    const NodeEntry nodeEntryWithLabel("foo");
    CPPUNIT_ASSERT(!nodeEntryWithLabel.parent());
    CPPUNIT_ASSERT_EQUAL("foo"s, nodeEntryWithLabel.label());
    CPPUNIT_ASSERT_EQUAL(list<string>{ "foo" }, nodeEntryWithLabel.path());
}

void EntryTests::testNesting()
{
    NodeEntry root("root");

    // create account under root
    auto *const account = new AccountEntry("account", &root);
    CPPUNIT_ASSERT_EQUAL_MESSAGE("account appended to root's children", vector<Entry *>{ account }, root.children());
    CPPUNIT_ASSERT_EQUAL_MESSAGE("account's path contains parent", list<string>{ "root" CPP_UTILITIES_PP_COMMA "account" }, account->path());
    CPPUNIT_ASSERT_EQUAL_MESSAGE("index initialized", 0, account->index());
    CPPUNIT_ASSERT_MESSAGE("actual assignment happened", account->parent() == &root);

    // create new node entry under root
    auto *const node = new NodeEntry("node", &root);
    CPPUNIT_ASSERT_EQUAL_MESSAGE("node appended to root's children", vector<Entry *>{ account CPP_UTILITIES_PP_COMMA node }, root.children());
    CPPUNIT_ASSERT_EQUAL_MESSAGE("account's path contains parent", list<string>{ "root" CPP_UTILITIES_PP_COMMA "node" }, node->path());
    CPPUNIT_ASSERT_EQUAL_MESSAGE("index initialized", 1, node->index());
    CPPUNIT_ASSERT_MESSAGE("actual assignment happened", node->parent() == &root);

    // nothing bad happens if we're setting the same parent again
    node->setParent(&root);
    CPPUNIT_ASSERT_EQUAL_MESSAGE("root's children not altered", vector<Entry *>{ account CPP_UTILITIES_PP_COMMA node }, root.children());
    CPPUNIT_ASSERT_EQUAL_MESSAGE("index not altered", 0, account->index());
    CPPUNIT_ASSERT_EQUAL_MESSAGE("index not altered", 1, node->index());

    // change the children's order
    node->setParent(&root, 0);
    CPPUNIT_ASSERT_EQUAL_MESSAGE("root's children not altered", vector<Entry *>{ node CPP_UTILITIES_PP_COMMA account }, root.children());
    CPPUNIT_ASSERT_EQUAL_MESSAGE("index updated", 1, account->index());
    CPPUNIT_ASSERT_EQUAL_MESSAGE("index updated", 0, node->index());

    // change the children's order the other way
    node->setParent(&root, 1);
    CPPUNIT_ASSERT_EQUAL_MESSAGE("root's children not altered", vector<Entry *>{ account CPP_UTILITIES_PP_COMMA node }, root.children());
    CPPUNIT_ASSERT_EQUAL_MESSAGE("index updated", 0, account->index());
    CPPUNIT_ASSERT_EQUAL_MESSAGE("index updated", 1, node->index());

    // specifying an invalid index inserts at the end
    auto *const anotherNode = new NodeEntry("another node", &root);
    anotherNode->setParent(&root, 2000);
    CPPUNIT_ASSERT_EQUAL_MESSAGE(
        "another node is at the end", vector<Entry *>{ account CPP_UTILITIES_PP_COMMA node CPP_UTILITIES_PP_COMMA anotherNode }, root.children());
    CPPUNIT_ASSERT_EQUAL_MESSAGE("index initialized", 2, anotherNode->index());

    // move node into another node
    node->setParent(anotherNode);
    CPPUNIT_ASSERT_EQUAL_MESSAGE("index not altered", 0, account->index());
    CPPUNIT_ASSERT_EQUAL_MESSAGE("index updated", 0, node->index());
    CPPUNIT_ASSERT_EQUAL_MESSAGE("index updated", 1, anotherNode->index());
    CPPUNIT_ASSERT_EQUAL_MESSAGE("root's childrens updated", vector<Entry *>{ account CPP_UTILITIES_PP_COMMA anotherNode }, root.children());
    CPPUNIT_ASSERT_EQUAL_MESSAGE("another node's childrens updated", vector<Entry *>{ node }, anotherNode->children());
    CPPUNIT_ASSERT_MESSAGE("node is still an indirect child of root", node->isIndirectChildOf(&root));
    CPPUNIT_ASSERT_MESSAGE("node is direct and hence also an indirect child of another node", node->isIndirectChildOf(anotherNode));
    CPPUNIT_ASSERT_MESSAGE("another node is no indirect child of node", !anotherNode->isIndirectChildOf(node));

    // replace children
    auto *const replacementNode = new NodeEntry("replacement", &root);
    CPPUNIT_ASSERT_EQUAL_MESSAGE("replacement's index initialized", 2, replacementNode->index());
    root.replaceChild(1, replacementNode);
    CPPUNIT_ASSERT_EQUAL_MESSAGE("root's childrens updated", vector<Entry *>{ account CPP_UTILITIES_PP_COMMA replacementNode }, root.children());
    CPPUNIT_ASSERT_MESSAGE("another node parentless", !anotherNode->parent());
    CPPUNIT_ASSERT_EQUAL_MESSAGE("another node's index updated", -1, anotherNode->index());
    CPPUNIT_ASSERT_EQUAL_MESSAGE("replacement's index updated", 1, replacementNode->index());

    // delete children
    anotherNode->setParent(&root, 0);
    CPPUNIT_ASSERT_EQUAL_MESSAGE("index updated", 0, anotherNode->index());
    CPPUNIT_ASSERT_EQUAL_MESSAGE("index updated", 1, account->index());
    CPPUNIT_ASSERT_EQUAL_MESSAGE("index updated", 2, replacementNode->index());
    root.deleteChildren(0, 1);
    CPPUNIT_ASSERT_EQUAL_MESSAGE("root's childrens updated", vector<Entry *>{ account CPP_UTILITIES_PP_COMMA replacementNode }, root.children());
    CPPUNIT_ASSERT_EQUAL_MESSAGE("index updated", 0, account->index());
    CPPUNIT_ASSERT_EQUAL_MESSAGE("index updated", 1, replacementNode->index());
}

void EntryTests::testEntryByPath()
{
    NodeEntry root("root");
    list<string> path;
    auto createNode = EntryType::Node;
    auto createAccount = EntryType::Account;

    CPPUNIT_ASSERT_MESSAGE("nullptr for empty path", !root.entryByPath(path));

    path = { "root" };
    CPPUNIT_ASSERT_EQUAL_MESSAGE("return current instance", static_cast<Entry *>(&root), root.entryByPath(path));

    path = { "root", "foo" };
    CPPUNIT_ASSERT_MESSAGE("nullptr for non-existant path", !root.entryByPath(path));

    path = { "root", "node" };
    const auto *const node = root.entryByPath(path, true, &createNode);
    CPPUNIT_ASSERT_MESSAGE("node created", node);
    CPPUNIT_ASSERT_EQUAL_MESSAGE("actually a node", EntryType::Node, node->type());
    CPPUNIT_ASSERT_EQUAL_MESSAGE("label assigned", "node"s, node->label());

    path = { "root", "account" };
    const auto *const account = root.entryByPath(path, true, &createAccount);
    CPPUNIT_ASSERT_MESSAGE("account created", account);
    CPPUNIT_ASSERT_EQUAL_MESSAGE("actually an account", EntryType::Account, account->type());
    CPPUNIT_ASSERT_EQUAL_MESSAGE("label assigned", "account"s, account->label());

    path = { "root", "account", "foo" };
    CPPUNIT_ASSERT_MESSAGE("nullptr for trying to add child to account", !root.entryByPath(path, true, &createAccount));

    path = { "root", "node", "foo" };
    const auto *const nestedAccount = root.entryByPath(path, true, &createAccount);
    CPPUNIT_ASSERT_MESSAGE("nested account created", nestedAccount);
    CPPUNIT_ASSERT_EQUAL_MESSAGE("nested account created", EntryType::Account, nestedAccount->type());
    CPPUNIT_ASSERT_EQUAL_MESSAGE("label assigned", "foo"s, nestedAccount->label());
    CPPUNIT_ASSERT_EQUAL_MESSAGE(
        "path actually correct", list<string>{ "root" CPP_UTILITIES_PP_COMMA "node" CPP_UTILITIES_PP_COMMA "foo" }, nestedAccount->path());
}

void EntryTests::testUniqueLabels()
{
    NodeEntry root("root");
    const auto *const fooEntry = new AccountEntry("foo", &root);
    VAR_UNUSED(fooEntry)
    const auto *const foo2Entry = new AccountEntry("foo", &root);
    CPPUNIT_ASSERT_EQUAL_MESSAGE("2nd foo renamed to foo 2", "foo 2"s, foo2Entry->label());
    const auto *const foo3Entry = new AccountEntry("foo", &root);
    CPPUNIT_ASSERT_EQUAL_MESSAGE("3rd foo renamed to foo 3", "foo 3"s, foo3Entry->label());
}
