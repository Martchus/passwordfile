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

std::string PASSWORD_FILE_EXPORT flagsToString(PasswordFileOpenFlags flags);

constexpr PasswordFileOpenFlags operator|(PasswordFileOpenFlags lhs, PasswordFileOpenFlags rhs)
{
    return static_cast<PasswordFileOpenFlags>(
        static_cast<std::underlying_type<PasswordFileOpenFlags>::type>(lhs) | static_cast<std::underlying_type<PasswordFileOpenFlags>::type>(rhs));
}

constexpr PasswordFileOpenFlags &operator|=(PasswordFileOpenFlags &lhs, PasswordFileOpenFlags rhs)
{
    return lhs = static_cast<PasswordFileOpenFlags>(static_cast<std::underlying_type<PasswordFileOpenFlags>::type>(lhs)
               | static_cast<std::underlying_type<PasswordFileOpenFlags>::type>(rhs));
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

std::string PASSWORD_FILE_EXPORT flagsToString(PasswordFileSaveFlags flags);

constexpr PasswordFileSaveFlags operator|(PasswordFileSaveFlags lhs, PasswordFileSaveFlags rhs)
{
    return static_cast<PasswordFileSaveFlags>(
        static_cast<std::underlying_type<PasswordFileSaveFlags>::type>(lhs) | static_cast<std::underlying_type<PasswordFileSaveFlags>::type>(rhs));
}

constexpr PasswordFileSaveFlags &operator|=(PasswordFileSaveFlags &lhs, PasswordFileSaveFlags rhs)
{
    return lhs = static_cast<PasswordFileSaveFlags>(static_cast<std::underlying_type<PasswordFileSaveFlags>::type>(lhs)
               | static_cast<std::underlying_type<PasswordFileSaveFlags>::type>(rhs));
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
    uint32 version() const;
    PasswordFileOpenFlags openOptions() const;
    PasswordFileSaveFlags saveOptions() const;
    std::string summary(PasswordFileSaveFlags saveOptions) const;

private:
    std::string m_path;
    std::string m_password;
    std::unique_ptr<NodeEntry> m_rootEntry;
    std::string m_extendedHeader;
    std::string m_encryptedExtendedHeader;
    IoUtilities::NativeFileStream m_file;
    IoUtilities::BinaryReader m_freader;
    IoUtilities::BinaryWriter m_fwriter;
    uint32 m_version;
    PasswordFileOpenFlags m_openOptions;
    PasswordFileSaveFlags m_saveOptions;
};

/*!
 * \brief Returns the underlying file stream.
 */
inline IoUtilities::NativeFileStream &PasswordFile::fileStream()
{
    return m_file;
}

/*!
 * \brief Returns the file version used the last time when saving the file (the version of the file as it is on the disk).
 * \remarks The version might change when re-saving with different options. See mininumVersion().
 */
inline uint32 PasswordFile::version() const
{
    return m_version;
}

/*!
 * \brief Returns the options used to open the file.
 */
inline PasswordFileOpenFlags PasswordFile::openOptions() const
{
    return m_openOptions;
}

/*!
 * \brief Returns the save options used the last time when saving the file.
 */
inline PasswordFileSaveFlags PasswordFile::saveOptions() const
{
    return m_saveOptions;
}

} // namespace Io

#endif // PASSWORD_FILE_IO_PASSWORD_FILE_H
