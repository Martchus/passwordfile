#ifndef ENTRY_H
#define ENTRY_H

#include "./field.h"

#include <c++utilities/conversion/types.h>

#include <iostream>
#include <list>
#include <string>
#include <vector>

namespace Io {

/*!
 * \brief Specifies the entry type.
 */
enum class EntryType : int {
    Node, /**< denotes a NodeEntry */
    Account /**< denotes an AccountEntry */
};

class NodeEntry;

class PASSWORD_FILE_EXPORT Entry {
    friend class NodeEntry;

public:
    virtual ~Entry();
    Entry &operator=(const Entry &other) = delete;
    virtual EntryType type() const = 0;
    const std::string &label() const;
    void setLabel(const std::string &label);
    void makeLabelUnique();
    NodeEntry *parent() const;
    void setParent(NodeEntry *parent, int index = -1);
    int index() const;
    bool isIndirectChildOf(NodeEntry *entry) const;
    std::list<std::string> path() const;
    void path(std::list<std::string> &res) const;
    virtual void make(std::ostream &stream) const = 0;
    virtual Entry *clone() const = 0;
    static Entry *parse(std::istream &stream);
    static bool denotesNodeEntry(byte version);
    static constexpr EntryType denotedEntryType(byte version);

protected:
    Entry(const std::string &label = std::string(), NodeEntry *parent = nullptr);
    Entry(const Entry &other);

private:
    std::string m_label;
    NodeEntry *m_parent;
    int m_index;

protected:
    std::string m_extendedData;
};

/*!
 * \brief Returns the label.
 */
inline const std::string &Entry::label() const
{
    return m_label;
}

/*!
 * \brief Sets the label.
 * \remarks The label might be modified to ensure that each child entry within a certain parent
 *          has a unique label.
 */
inline void Entry::setLabel(const std::string &label)
{
    m_label = label;
    makeLabelUnique();
}

/*!
 * \brief Returns the parent entry.
 * \remarks Returns nullptr for top-level entries.
 */
inline NodeEntry *Entry::parent() const
{
    return m_parent;
}

/*!
 * \brief Returns the index of the entry within its parent. Returns -1 for parentless entries.
 */
inline int Entry::index() const
{
    return m_index;
}

class PASSWORD_FILE_EXPORT NodeEntry : public Entry {
    friend class Entry;

public:
    NodeEntry();
    NodeEntry(const std::string &label, NodeEntry *parent = nullptr);
    NodeEntry(std::istream &stream);
    NodeEntry(const NodeEntry &other);
    ~NodeEntry();

    virtual EntryType type() const;
    const std::vector<Entry *> &children() const;
    void deleteChildren(int begin, int end);
    void replaceChild(std::size_t at, Entry *newChild);
    Entry *entryByPath(std::list<std::string> &path, bool includeThis = true, EntryType *creationType = nullptr);
    bool isExpandedByDefault() const;
    void setExpandedByDefault(bool expandedByDefault);
    virtual void make(std::ostream &stream) const;
    virtual NodeEntry *clone() const;

private:
    std::vector<Entry *> m_children;
    bool m_expandedByDefault;
};

inline EntryType NodeEntry::type() const
{
    return EntryType::Node;
}

inline const std::vector<Entry *> &NodeEntry::children() const
{
    return m_children;
}

inline bool NodeEntry::isExpandedByDefault() const
{
    return m_expandedByDefault;
}

inline void NodeEntry::setExpandedByDefault(bool expandedByDefault)
{
    m_expandedByDefault = expandedByDefault;
}

inline bool Entry::denotesNodeEntry(byte version)
{
    return (version & 0x80) == 0;
}

constexpr EntryType Entry::denotedEntryType(byte version)
{
    return (version & 0x80) == 0 ? EntryType::Node : EntryType::Account;
}

class PASSWORD_FILE_EXPORT AccountEntry : public Entry {
public:
    AccountEntry();
    AccountEntry(const std::string &label, NodeEntry *parent = nullptr);
    AccountEntry(std::istream &stream);
    AccountEntry(const AccountEntry &other);
    ~AccountEntry();

    virtual EntryType type() const;
    const std::vector<Field> &fields() const;
    std::vector<Field> &fields();
    virtual void make(std::ostream &stream) const;
    virtual AccountEntry *clone() const;

private:
    std::vector<Field> m_fields;
};

inline EntryType AccountEntry::type() const
{
    return EntryType::Account;
}

inline const std::vector<Field> &AccountEntry::fields() const
{
    return m_fields;
}

inline std::vector<Field> &AccountEntry::fields()
{
    return m_fields;
}
} // namespace Io

#endif // ENTRY_H
