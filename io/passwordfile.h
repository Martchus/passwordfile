#ifndef PASSWORD_FILE_IO_PASSWORD_FILE_H
#define PASSWORD_FILE_IO_PASSWORD_FILE_H

#include "../global.h"

#include <c++utilities/io/binaryreader.h>
#include <c++utilities/io/binarywriter.h>
#include <c++utilities/io/nativefilestream.h>

#include <fstream>
#include <iostream>
#include <memory>
#include <string>

namespace Io {

class NodeEntry;

enum class PasswordFileOpenFlags : uint64 {
    None = 0,
    ReadOnly = 1,
    Default = None,
};

constexpr PasswordFileOpenFlags operator|(PasswordFileOpenFlags lhs, PasswordFileOpenFlags rhs)
{
    return static_cast<PasswordFileOpenFlags>(
        static_cast<std::underlying_type<PasswordFileOpenFlags>::type>(lhs) | static_cast<std::underlying_type<PasswordFileOpenFlags>::type>(rhs));
}

constexpr PasswordFileOpenFlags operator|=(PasswordFileOpenFlags lhs, PasswordFileOpenFlags rhs)
{
    return static_cast<PasswordFileOpenFlags>(
        static_cast<std::underlying_type<PasswordFileOpenFlags>::type>(lhs) | static_cast<std::underlying_type<PasswordFileOpenFlags>::type>(rhs));
}

constexpr bool operator&(PasswordFileOpenFlags lhs, PasswordFileOpenFlags rhs)
{
    return static_cast<bool>(
        static_cast<std::underlying_type<PasswordFileOpenFlags>::type>(lhs) & static_cast<std::underlying_type<PasswordFileOpenFlags>::type>(rhs));
}

enum class PasswordFileSaveFlags : uint64 {
    None = 0,
    Encryption = 1,
    Compression = 2,
    PasswordHashing = 4,
    Default = Encryption | Compression | PasswordHashing,
};

constexpr PasswordFileSaveFlags operator|(PasswordFileSaveFlags lhs, PasswordFileSaveFlags rhs)
{
    return static_cast<PasswordFileSaveFlags>(
        static_cast<std::underlying_type<PasswordFileSaveFlags>::type>(lhs) | static_cast<std::underlying_type<PasswordFileSaveFlags>::type>(rhs));
}

constexpr PasswordFileSaveFlags operator|=(PasswordFileSaveFlags lhs, PasswordFileSaveFlags rhs)
{
    return static_cast<PasswordFileSaveFlags>(
        static_cast<std::underlying_type<PasswordFileSaveFlags>::type>(lhs) | static_cast<std::underlying_type<PasswordFileSaveFlags>::type>(rhs));
}

constexpr bool operator&(PasswordFileSaveFlags lhs, PasswordFileSaveFlags rhs)
{
    return static_cast<bool>(
        static_cast<std::underlying_type<PasswordFileSaveFlags>::type>(lhs) & static_cast<std::underlying_type<PasswordFileSaveFlags>::type>(rhs));
}

class PASSWORD_FILE_EXPORT PasswordFile {
public:
    explicit PasswordFile();
    explicit PasswordFile(const std::string &path, const std::string &password);
    PasswordFile(const PasswordFile &other);
    PasswordFile(PasswordFile &&other);
    ~PasswordFile();
    IoUtilities::NativeFileStream &fileStream();
    void open(PasswordFileOpenFlags options = PasswordFileOpenFlags::Default);
    void opened();
    void generateRootEntry();
    void create();
    void close();
    void load();
    uint32 mininumVersion(PasswordFileSaveFlags options) const;
    void save(PasswordFileSaveFlags options = PasswordFileSaveFlags::Default);
    void write(PasswordFileSaveFlags options = PasswordFileSaveFlags::Default);
    void clearEntries();
    void clear();
    void exportToTextfile(const std::string &targetPath) const;
    void doBackup();
    bool hasRootEntry() const;
    const NodeEntry *rootEntry() const;
    NodeEntry *rootEntry();
    const std::string &path() const;
    const std::string &password() const;
    void setPath(const std::string &value);
    void clearPath();
    void setPassword(const std::string &password);
    void setPassword(const char *password, const std::size_t passwordSize);
    void clearPassword();
    bool isEncryptionUsed();
    bool isOpen() const;
    std::string &extendedHeader();
    const std::string &extendedHeader() const;
    std::string &encryptedExtendedHeader();
    const std::string &encryptedExtendedHeader() const;
    std::size_t size();

private:
    std::string m_path;
    std::string m_password;
    std::unique_ptr<NodeEntry> m_rootEntry;
    std::string m_extendedHeader;
    std::string m_encryptedExtendedHeader;
    IoUtilities::NativeFileStream m_file;
    IoUtilities::BinaryReader m_freader;
    IoUtilities::BinaryWriter m_fwriter;
};

/*!
 * \brief Returns the underlying file stream.
 */
inline IoUtilities::NativeFileStream &PasswordFile::fileStream()
{
    return m_file;
}

} // namespace Io

#endif // PASSWORD_FILE_IO_PASSWORD_FILE_H
