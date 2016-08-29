#ifndef PASSWORDFILE_H
#define PASSWORDFILE_H

#include "../global.h"

#include <c++utilities/io/binaryreader.h>
#include <c++utilities/io/binarywriter.h>

#include <string>
#include <iostream>
#include <fstream>
#include <memory>

namespace Io {

class NodeEntry;

class PASSWORD_FILE_EXPORT PasswordFile
{   
public:
    explicit PasswordFile();
    explicit PasswordFile(const std::string &path, const std::string &password);
    PasswordFile(const PasswordFile &other);
    ~PasswordFile();
    void open(bool readOnly = false);
    void generateRootEntry();
    void create();
    void close();
    void load();
    void save(bool useEncryption = true, bool useCompression = true);
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
    size_t size();
private:
    std::string m_path;
    char m_password[32];
    std::unique_ptr<NodeEntry> m_rootEntry;
    std::string m_extendedHeader;
    std::string m_encryptedExtendedHeader;
    std::fstream m_file;
    IoUtilities::BinaryReader m_freader;
    IoUtilities::BinaryWriter m_fwriter;
};

}

#endif // PASSWORDFILE_H
