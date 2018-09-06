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

class PASSWORD_FILE_EXPORT PasswordFile {
public:
    explicit PasswordFile();
    explicit PasswordFile(const std::string &path, const std::string &password);
    PasswordFile(const PasswordFile &other);
    PasswordFile(PasswordFile &&other);
    ~PasswordFile();
    IoUtilities::NativeFileStream &fileStream();
    void open(bool readOnly = false);
    void opened();
    void generateRootEntry();
    void create();
    void close();
    void load();
    // FIXME: use flags in v4
    void save(bool useEncryption = true, bool useCompression = true);
    void write(bool useEncryption = true, bool useCompression = true);
    void clearEntries();
    void clear();
    void exportToTextfile(const std::string &targetPath) const;
    void doBackup();
    bool hasRootEntry() const;
    const NodeEntry *rootEntry() const;
    NodeEntry *rootEntry();
    const std::string &path() const;
    const char *password() const;
    void setPath(const std::string &value);
    void clearPath();
    void setPassword(const std::string &value);
    void clearPassword();
    bool isEncryptionUsed();
    bool isOpen() const;
    std::size_t size();

private:
    std::string m_path;
    char m_password[32];
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
