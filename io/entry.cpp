#include "./entry.h"
#include "./parsingexception.h"

#include <c++utilities/io/binaryreader.h>
#include <c++utilities/io/binarywriter.h>

#include <algorithm>
#include <sstream>

using namespace std;
using namespace IoUtilities;
using namespace ConversionUtilities;

namespace Io {

/*!
 * \namespace Io
 * \brief Contains all IO related classes.
 */

/*!
 * \class Entry
 * \brief Instances of the Entry class form a hierarchic data strucutre used to store
 *        account information.
 *
 * Entries can be serialized and deserialized using the parse() and make() methods.
 */

/*!
 * \brief Constructs a new entry with the specified \a label and \a parent.
 */
Entry::Entry(const string &label, NodeEntry *parent)
    : m_parent(nullptr)
    , m_index(-1)
{
    setParent(parent);
    setLabel(label);
}

/*!
 * \brief Constructs a copy of another entry.
 * \remarks The copy will be parentless and thus not be embedded in the hierarchy
 *          of \a other. Child entries will be copied as well.
 */
Entry::Entry(const Entry &other)
    : m_label(other.m_label)
    , m_parent(nullptr)
    , m_index(-1)
{
}

/*!
 * \brief Destroys the entry.
 */
Entry::~Entry()
{
    setParent(nullptr);
}

/*!
 * \brief Internally called to make the label unique.
 * \sa setLabel()
 */
void Entry::makeLabelUnique()
{
    if (m_parent) {
        int index = 1;
        string currentLabel(label());
    checkLabel:
        for (Entry *sibling : m_parent->children()) {
            if (sibling != this && currentLabel == sibling->label()) {
                stringstream newLabel(currentLabel);
                newLabel.seekp(0, ios_base::end);
                if (newLabel.tellp()) {
                    newLabel << ' ';
                }
                newLabel << ++index;
                currentLabel = newLabel.str();
                goto checkLabel;
            }
        }
        m_label = currentLabel;
    }
}

/*!
 * \brief Sets the \a parent for the entry.
 *
 * If an \a index is specified the entry will be inserted as child at this position.
 * If \a parent is nullptr, the entry will be parentless.
 */
void Entry::setParent(NodeEntry *parent, int index)
{
    if (m_parent != parent || (m_index != index && index >= 0)) {
        if (m_parent) {
            m_parent->m_children.erase(m_parent->m_children.begin() + m_index);
            for (auto i = m_parent->m_children.begin() + m_index; i < m_parent->m_children.end(); ++i) {
                (*i)->m_index -= 1;
            }
        }
        if (parent) {
            if (index < 0 || static_cast<size_t>(index) >= parent->m_children.size()) {
                m_index = parent->m_children.size();
                parent->m_children.push_back(this);
            } else {
                for (auto i = parent->m_children.insert(parent->m_children.begin() + index, this) + 1; i != parent->m_children.end(); ++i) {
                    (*i)->m_index += 1;
                }
                m_index = index;
            }
        } else {
            m_index = -1;
        }
        m_parent = parent;
        makeLabelUnique();
    }
}

/*!
 * \brief Returns an indication whether the instance is an indirect child of the specified \a entry.
 */
bool Entry::isIndirectChildOf(NodeEntry *entry) const
{
    if (parent()) {
        if (parent() == entry) {
            return true;
        } else {
            return parent()->isIndirectChildOf(entry);
        }
    } else {
        return false;
    }
}

/*!
 * \brief Returns the path of the entry.
 */
std::list<string> Entry::path() const
{
    list<string> res;
    path(res);
    return res;
}

/*!
 * \brief Stores to path of the entry in the specified list of string.
 */
void Entry::path(std::list<string> &res) const
{
    if (m_parent) {
        m_parent->path(res);
    }
    res.push_back(label());
}

/*!
 * \brief Parses an entry from the specified \a stream.
 * \throws Throws ParsingException when a parsing exception occurs.
 */
Entry *Entry::parse(istream &stream)
{
    byte version = stream.peek();
    if (denotesNodeEntry(version)) {
        return new NodeEntry(stream);
    } else {
        return new AccountEntry(stream);
    }
}

/*!
 * \fn Entry::type()
 * \brief Returns the type of the entry.
 */

/*!
 * \fn Entry::make()
 * \brief Serializes the entry to the specified \a stream.
 */

/*!
 * \fn Entry::clone()
 * \brief Clones the entry.
 * \remarks The copy will be parentless and thus not be embedded in the hierarchy
 *          of \a other. Child entries will be copied as well.
 */

/*!
 * \class NodeEntry
 * \brief The NodeEntry class acts as parent for other entries.
 */

/*!
 * \brief Constructs a new node entry.
 */
NodeEntry::NodeEntry()
    : Entry()
    , m_expandedByDefault(true)
{
}

/*!
 * \brief Constructs a new node entry with the specified \a label and \a parent.
 */
NodeEntry::NodeEntry(const string &label, NodeEntry *parent)
    : Entry(label, parent)
    , m_expandedByDefault(true)
{
}

/*!
 * \brief Constructs a new node entry which is deserialized from the specified \a stream.
 */
NodeEntry::NodeEntry(istream &stream)
    : m_expandedByDefault(true)
{
    BinaryReader reader(&stream);
    byte version = reader.readByte();
    if (denotesNodeEntry(version)) {
        if (version == 0x0 || version == 0x1) {
            setLabel(reader.readLengthPrefixedString());
            if (version == 0x1) { // version 0x1 has an extended header
                uint16 extendedHeaderSize = reader.readUInt16BE();
                if (extendedHeaderSize >= 1) {
                    byte flags = reader.readByte();
                    m_expandedByDefault = flags & 0x80;
                    extendedHeaderSize -= 1;
                }
                m_extendedData = reader.readString(extendedHeaderSize);
            }
            uint32 childCount = reader.readUInt32BE();
            for (uint32 i = 0; i < childCount; ++i) {
                Entry::parse(stream)->setParent(this);
            }
        } else {
            throw ParsingException("Entry version not supported.");
        }
    } else {
        throw ParsingException("Node entry expected.");
    }
}

/*!
 * \brief Constructs a copy of the another entry.
 * \remarks The copy will be parentless and thus not be embedded in the hierarchy
 *          of \a other. Child entries will be copied as well.
 */
NodeEntry::NodeEntry(const NodeEntry &other)
    : Entry(other)
{
    for (Entry *otherChild : other.m_children) {
        Entry *clonedChild = otherChild->clone();
        clonedChild->m_parent = this;
        clonedChild->m_index = m_children.size();
        m_children.push_back(clonedChild);
    }
}

/*!
 * \brief Destroys the entry.
 */
NodeEntry::~NodeEntry()
{
    for (Entry *child : m_children) {
        child->m_parent = nullptr;
        delete child;
    }
}

/*!
 * \brief Deletes children from the node entry.
 * \param begin Specifies the index of the first children to delete.
 * \param end Specifies the index after the last children to delete.
 */
void NodeEntry::deleteChildren(int begin, int end)
{
    auto iterator = m_children.cbegin() + begin;
    auto endIterator = m_children.begin() + end;
    for (; iterator < endIterator; ++iterator) {
        (*iterator)->m_parent = nullptr;
        delete *iterator;
    }
    m_children.erase(m_children.begin() + begin, endIterator);
}

/*!
 * \brief Replaces the child \a at the specified index with the specified \a newChild.
 */
void NodeEntry::replaceChild(size_t at, Entry *newChild)
{
    if (at < m_children.size()) {
        m_children.at(at)->m_parent = nullptr;
        m_children[at] = newChild;
    }
}

/*!
 * \brief Returns an entry specified by the provided \a path.
 * \param path Specifies the path of the entry to be returned.
 * \param includeThis Specifies whether the current instance should be included.
 * \param creationType Specifies a pointer which dereferenced value determines what kind of entry should be created
 *                     if the entry specified by the provided \a path does not exist. The parent of the entry
 *                     to be created must exist. Specify nullptr if no entries should be created (default).
 * \returns Returns the entry if found (or created); otherwise nullptr is returned.
 */
Entry *NodeEntry::entryByPath(list<string> &path, bool includeThis, EntryType *creationType)
{
    if (path.size()) {
        if (includeThis) {
            if (path.front() == label()) {
                path.pop_front();
            } else {
                return nullptr;
            }
        }
        if (path.size()) {
            for (Entry *child : m_children) {
                if (path.front() == child->label()) {
                    path.pop_front();
                    if (path.empty()) {
                        return child;
                    } else if (child->type() == EntryType::Node) {
                        return static_cast<NodeEntry *>(child)->entryByPath(path, false, creationType);
                    } else {
                        return nullptr; // can not resolve path since an account entry can not have children
                    }
                }
            }
            if (creationType) {
                if (path.size() == 1) {
                    switch (*creationType) {
                    case EntryType::Account:
                        return new AccountEntry(path.front(), this);
                    case EntryType::Node:
                        return new NodeEntry(path.front(), this);
                    }
                } else {
                    return nullptr;
                }
            }
        } else {
            return this;
        }
    }
    return nullptr;
}

void NodeEntry::make(ostream &stream) const
{
    BinaryWriter writer(&stream);
    writer.writeByte(isExpandedByDefault() && m_extendedData.empty() ? 0x0 : 0x1); // version
    writer.writeLengthPrefixedString(label());
    if (!isExpandedByDefault() || !m_extendedData.empty()) {
        writer.writeUInt16BE(1 + m_extendedData.size()); // extended header is 1 byte long
        byte flags = 0x00;
        if (isExpandedByDefault()) {
            flags |= 0x80;
        }
        writer.writeByte(flags);
        writer.writeString(m_extendedData);
    }
    writer.writeUInt32BE(m_children.size());
    for (const Entry *child : m_children) {
        child->make(stream);
    }
}

NodeEntry *NodeEntry::clone() const
{
    return new NodeEntry(*this);
}

/*!
 * \class AccountEntry
 * \brief The exception that is thrown when a parsing error occurs.
 */

AccountEntry::AccountEntry()
{
}

/*!
 * \brief Constructs a new account entry with the specified \a label and \a parent.
 */
AccountEntry::AccountEntry(const string &label, NodeEntry *parent)
    : Entry(label, parent)
{
}

/*!
 * \brief Constructs a new account entry which is deserialized from the specified \a stream.
 */
AccountEntry::AccountEntry(istream &stream)
{
    BinaryReader reader(&stream);
    byte version = reader.readByte();
    if (!denotesNodeEntry(version)) {
        version ^= 0x80; // set bit 0 to false
        if (version == 0x0 || version == 0x1) {
            setLabel(reader.readLengthPrefixedString());
            if (version == 0x1) { // version 0x1 has an extended header
                uint16 extendedHeaderSize = reader.readUInt16BE();
                // currently there's nothing to read here
                m_extendedData = reader.readString(extendedHeaderSize);
            }
            uint32 fieldCount = reader.readUInt32BE();
            for (uint32 i = 0; i < fieldCount; ++i) {
                m_fields.push_back(Field(this, stream));
            }
        } else {
            throw ParsingException("Entry version not supported.");
        }
    } else {
        throw ParsingException("Account entry expected.");
    }
}

/*!
 * \brief Constructs a copy of the another entry.
 * \remarks The copy will be parentless and thus not be embedded in the hierarchy
 *          of \a other. Child entries will be copied as well.
 */
AccountEntry::AccountEntry(const AccountEntry &other)
    : Entry(other)
{
    m_fields = other.m_fields;
}

/*!
 * \brief Destroys the entry.
 */
AccountEntry::~AccountEntry()
{
}

void AccountEntry::make(ostream &stream) const
{
    BinaryWriter writer(&stream);
    writer.writeByte(0x80 | (m_extendedData.empty() ? 0x0 : 0x1)); // version
    writer.writeLengthPrefixedString(label());
    if (!m_extendedData.empty()) {
        writer.writeUInt16BE(m_extendedData.size());
        writer.writeString(m_extendedData);
    }
    writer.writeUInt32BE(m_fields.size());
    for (const Field &field : m_fields) {
        field.make(stream);
    }
}

AccountEntry *AccountEntry::clone() const
{
    return new AccountEntry(*this);
}
}
