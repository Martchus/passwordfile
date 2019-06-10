#include "./field.h"
#include "./parsingexception.h"

#include <c++utilities/io/binaryreader.h>
#include <c++utilities/io/binarywriter.h>

using namespace std;
using namespace CppUtilities;

namespace Io {

/*!
 * \class Field
 * \brief The Field class holds field information which consists of a name and a value
 *        and is able to serialize and deserialize this information.
 */

/*!
 * \brief Constructs a new account entry for the specified account with the specified \a name
 *        and \a value.
 */
Field::Field(AccountEntry *tiedAccount, const string &name, const string &value)
    : m_name(name)
    , m_value(value)
    , m_type(FieldType::Normal)
    , m_tiedAccount(tiedAccount)
{
}

/*!
 * \brief Constructs a new account entry for the specified account which is deserialize from
 *        the specified \a stream.
 * \throws Throws ParsingException when an parsing error occurs.
 */
Field::Field(AccountEntry *tiedAccount, istream &stream)
{
    BinaryReader reader(&stream);
    const int version = reader.readByte();
    if (version != 0x0 && version != 0x1) {
        throw ParsingException("Field version is not supported.");
    }
    m_name = reader.readLengthPrefixedString();
    m_value = reader.readLengthPrefixedString();
    std::uint8_t type = reader.readByte();
    if (!isValidType(type)) {
        throw ParsingException("Field type is not supported.");
    }
    m_type = static_cast<FieldType>(type);
    // read extended header for version 0x1
    if (version == 0x1) {
        const std::uint16_t extendedHeaderSize = reader.readUInt16BE();
        // currently there's nothing to read here
        m_extendedData = reader.readString(extendedHeaderSize);
    }
    m_tiedAccount = tiedAccount;
}

/*!
 * \brief Serializes the current instance to the specified \a stream.
 */
void Field::make(ostream &stream) const
{
    BinaryWriter writer(&stream);
    writer.writeByte(m_extendedData.empty() ? 0x0 : 0x1); // version
    writer.writeLengthPrefixedString(m_name);
    writer.writeLengthPrefixedString(m_value);
    writer.writeByte(static_cast<std::uint8_t>(m_type));
    if (!m_extendedData.empty()) {
        writer.writeUInt16BE(m_extendedData.size());
        writer.writeString(m_extendedData);
    }
}
} // namespace Io
