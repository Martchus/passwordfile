#ifndef FIELD_H
#define FIELD_H

#include "../global.h"

#include <iostream>
#include <string>

namespace Io {

enum class FieldType : int { Normal, Password };

class AccountEntry;

class PASSWORD_FILE_EXPORT Field {
public:
    Field(AccountEntry *tiedAccount, const std::string &name = std::string(), const std::string &value = std::string());
    Field(AccountEntry *tiedAccount, std::istream &stream);

    bool isEmpty() const;
    const std::string &name() const;
    void setName(const std::string &name);
    const std::string &value() const;
    void setValue(const std::string &value);
    FieldType type() const;
    void setType(FieldType type);
    AccountEntry *tiedAccount() const;
    void make(std::ostream &stream) const;
    static bool isValidType(int number);

private:
    std::string m_name;
    std::string m_value;
    FieldType m_type;
    AccountEntry *m_tiedAccount;

protected:
    std::string m_extendedData;
};

/*!
 * \brief Returns an indication whether the entry is empty.
 */
inline bool Field::isEmpty() const
{
    return m_name.empty() && m_value.empty();
}

/*!
 * \brief Returns the name.
 */
inline const std::string &Field::name() const
{
    return m_name;
}

/*!
 * \brief Sets the name.
 */
inline void Field::setName(const std::string &name)
{
    m_name = name;
}

/*!
 * \brief Returns the value.
 */
inline const std::string &Field::value() const
{
    return m_value;
}

/*!
 * \brief Sets the value.
 */
inline void Field::setValue(const std::string &value)
{
    m_value = value;
}

/*!
 * \brief Returns the type.
 */
inline FieldType Field::type() const
{
    return m_type;
}

/*!
 * \brief Sets the type.
 */
inline void Field::setType(FieldType type)
{
    m_type = type;
}

/*!
 * \brief Returns the tied account.
 */
inline AccountEntry *Field::tiedAccount() const
{
    return m_tiedAccount;
}

/*!
 * \brief Returns whether the specified \a number is a valid field type.
 */
inline bool Field::isValidType(int number)
{
    return number >= 0 && number <= 1;
}
} // namespace Io

#endif // FIELD_H
