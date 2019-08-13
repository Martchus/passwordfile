#ifndef PASSWORD_FILE_IO_PASSWORD_FILE_H
#define PASSWORD_FILE_IO_PASSWORD_FILE_H

#include "../global.h"

#include <c++utilities/io/binaryreader.h>
#include <c++utilities/io/binarywriter.h>
#include <c++utilities/io/nativefilestream.h>
#include <c++utilities/misc/flagenumclass.h>

#include <cstdint>
#include <fstream>
#include <iostream>
#include <memory>
#include <string>

namespace Io {

class NodeEntry;

enum class PasswordFileOpenFlags : std::uint64_t {
    None = 0,
    ReadOnly = 1,
    Default = None,
};

std::string PASSWORD_FILE_EXPORT flagsToString(PasswordFileOpenFlags flags);

enum class PasswordFileSaveFlags : std::uint64_t {
    None = 0,
    Encryption = 1,
    Compression = 2,
    PasswordHashing = 4,
    AllowToCreateNewFile = 8,
    Default = Encryption | Compression | PasswordHashing | AllowToCreateNewFile,
};

std::string PASSWORD_FILE_EXPORT flagsToString(PasswordFileSaveFlags flags);

class PASSWORD_FILE_EXPORT PasswordFile {
public:
    explicit PasswordFile();
    explicit PasswordFile(const std::string &path, const std::string &password);
    PasswordFile(const PasswordFile &other);
    PasswordFile(PasswordFile &&other);
    ~PasswordFile();
    CppUtilities::NativeFileStream &fileStream();
    void open(PasswordFileOpenFlags options = PasswordFileOpenFlags::Default);
    void opened();
    void generateRootEntry();
    void create();
    void close();
    void load();
    std::uint32_t mininumVersion(PasswordFileSaveFlags options) const;
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
    std::uint32_t version() const;
    PasswordFileOpenFlags openOptions() const;
    PasswordFileSaveFlags saveOptions() const;
    std::string summary(PasswordFileSaveFlags saveOptions) const;

private:
    std::string m_path;
    std::string m_password;
    std::unique_ptr<NodeEntry> m_rootEntry;
    std::string m_extendedHeader;
    std::string m_encryptedExtendedHeader;
    CppUtilities::NativeFileStream m_file;
    CppUtilities::BinaryReader m_freader;
    CppUtilities::BinaryWriter m_fwriter;
    std::uint32_t m_version;
    PasswordFileOpenFlags m_openOptions;
    PasswordFileSaveFlags m_saveOptions;
};

/*!
 * \brief Returns the underlying file stream.
 */
inline CppUtilities::NativeFileStream &PasswordFile::fileStream()
{
    return m_file;
}

/*!
 * \brief Returns the current file path.
 */
inline const std::string &PasswordFile::path() const
{
    return m_path;
}

/*!
 * \brief Clears the current path. Causes the file to be closed if currently opened.
 */
inline void PasswordFile::clearPath()
{
    close();
    m_path.clear();
}

/*!
 * \brief Returns the current password. It will be used when loading or saving using encryption.
 */
inline const std::string &PasswordFile::password() const
{
    return m_password;
}

/*!
 * \brief Sets the current password. It will be used when loading an encrypted file or when saving using encryption.
 */
inline void PasswordFile::setPassword(const std::string &password)
{
    m_password = password;
}

/*!
 * \brief Sets the current password. It will be used when loading an encrypted file or when saving using encryption.
 */
inline void PasswordFile::setPassword(const char *password, const size_t passwordSize)
{
    m_password.assign(password, passwordSize);
}

/*!
 * \brief Clears the current password.
 */
inline void PasswordFile::clearPassword()
{
    m_password.clear();
}

/*!
 * \brief Returns an indication whether the file is open.
 */
inline bool PasswordFile::isOpen() const
{
    return m_file.is_open();
}

/*!
 * \brief Returns the extended header.
 */
inline std::string &PasswordFile::extendedHeader()
{
    return m_extendedHeader;
}

/*!
 * \brief Returns the extended header.
 */
inline const std::string &PasswordFile::extendedHeader() const
{
    return m_extendedHeader;
}

/*!
 * \brief Returns the encrypted extended header.
 */
inline std::string &PasswordFile::encryptedExtendedHeader()
{
    return m_encryptedExtendedHeader;
}

/*!
 * \brief Returns the encrypted extended header.
 */
inline const std::string &PasswordFile::encryptedExtendedHeader() const
{
    return m_encryptedExtendedHeader;
}

/*!
 * \brief Returns the file version used the last time when saving the file (the version of the file as it is on the disk).
 * \remarks The version might change when re-saving with different options. See mininumVersion().
 */
inline std::uint32_t PasswordFile::version() const
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

CPP_UTILITIES_MARK_FLAG_ENUM_CLASS(Io, Io::PasswordFileOpenFlags);
CPP_UTILITIES_MARK_FLAG_ENUM_CLASS(Io, Io::PasswordFileSaveFlags);

#endif // PASSWORD_FILE_IO_PASSWORD_FILE_H
