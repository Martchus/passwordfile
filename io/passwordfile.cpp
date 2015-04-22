#include "passwordfile.h"
#include "cryptoexception.h"
#include "parsingexception.h"
#include "entry.h"

#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <zlib.h>

#include <streambuf>
#include <sstream>
#include <cstring>
#include <memory>
#include <functional>

using namespace std;
using namespace IoUtilities;

namespace Io {

const unsigned int aes256cbcIvSize = 16U;

/*!
 * \class PasswordFile
 * \brief The PasswordFile class holds account information in the form of Entry and Field instances
 *        and provides methods to read and write these information to encrypted files using OpenSSL.
 */

/*!
 * \brief Constructs a new password file.
 */
PasswordFile::PasswordFile() :
    m_freader(BinaryReader(&m_file)),
    m_fwriter(BinaryWriter(&m_file))
{
    m_file.exceptions(ios_base::failbit | ios_base::badbit);
    clearPassword();
}

/*!
 * \brief Constructs a new password file with the specified \a path and \a password.
 */
PasswordFile::PasswordFile(const string &path, const string &password) :
    m_freader(BinaryReader(&m_file)),
    m_fwriter(BinaryWriter(&m_file))
{
    m_file.exceptions(ios_base::failbit | ios_base::badbit);
    setPath(path);
    setPassword(password);
}

/*!
 * \brief Constructs a copy of another password file.
 */
PasswordFile::PasswordFile(const PasswordFile &other) :
    m_path(other.m_path),
    m_freader(BinaryReader(&m_file)),
    m_fwriter(BinaryWriter(&m_file))
{
    m_file.exceptions(ios_base::failbit | ios_base::badbit);
    setPath(other.path());
    memcpy(m_password, other.m_password, 32);
}

/*!
 * \brief Closes the file if still opened and destroys the instance.
 */
PasswordFile::~PasswordFile()
{
    close();
}

/*!
 * \brief Opens the file. Does not load the contents (see load()).
 * \throws Throws ios_base::failure when an IO error occurs.
 */
void PasswordFile::open(bool readOnly)
{
    close();
    if(m_path.empty()) {
        throw ios_base::failure("Unable to open file because path is emtpy.");
    }
    m_file.open(m_path, readOnly ? ios_base::in | ios_base::binary : ios_base::in | ios_base::out | ios_base::binary);
    m_file.seekg(0, ios_base::end);
    if(m_file.tellg() == 0) {
        throw ios_base::failure("File is empty.");
    } else {
        m_file.seekg(0);
    }
}

/*!
 * \brief Generates a new root entry for the file.
 */
void PasswordFile::generateRootEntry()
{
    if(!m_rootEntry) {
        m_rootEntry.reset(new NodeEntry("accounts"));
    }
}

/*!
 * \brief Creates the file. Does not generate a new root element (see generateRootElement()).
 * \throws Throws ios_base::failure when an IO error occurs.
 */
void PasswordFile::create()
{
    close();
    if(m_path.empty()) {
        throw ios_base::failure("Unable to create file because path is empty.");
    }
    m_file.open(m_path, fstream::out | fstream::trunc | fstream::binary);
}

/*!
 * \brief Reads the contents of the file. Opens the file if not already opened. Replaces
 *        the current root entry with the new one constructed from the file contents.
 * \throws Throws ios_base::failure when an IO error occurs.
 * \throws Throws Io::ParsingException when a parsing error occurs.
 * \throws Throws Io::CryptoException when a decryption error occurs.
 * \throws Throws ConversionUtilities::ConversionException when a conversion error occurs.
 */
void PasswordFile::load()
{
    if(!m_file.is_open()) {
        open();
    }
    m_file.seekg(0);
    // check magic number
    if(m_freader.readUInt32LE() != 0x7770616DU) {
        throw ParsingException("Signature not present.");
    }
    // check version and flags (used in version 0x3 only)
    uint32 version = m_freader.readUInt32LE();
    if(version != 0x0U && version != 0x1U && version != 0x2U && version != 0x3U)
        throw ParsingException("Version is unknown.");
    bool decrypterUsed;
    bool ivUsed;
    bool compressionUsed;
    if(version == 0x3U) {
        byte flags = m_freader.readByte();
        decrypterUsed = flags & 0x80;
        ivUsed = flags & 0x40;
        compressionUsed = flags & 0x20;
    } else {
        decrypterUsed = version >= 0x1U;
        ivUsed = version == 0x2U;
        compressionUsed = false;
    }
    // get length
    fstream::pos_type headerSize = m_file.tellg();
    m_file.seekg(0, ios_base::end);
    fstream::pos_type size = m_file.tellg();
    m_file.seekg(headerSize, ios_base::beg);
    size -= headerSize;
    // read file
    unsigned char iv[aes256cbcIvSize] = {0};
    if(decrypterUsed && ivUsed) {
        if(size < aes256cbcIvSize) {
            throw ParsingException("Initiation vector not present.");
        }
        m_file.read(reinterpret_cast<char *>(iv), aes256cbcIvSize);
        size -= aes256cbcIvSize;
    }
    if(size <= 0) {
        throw ParsingException("No contents found.");
    }
    // decrypt contents
    vector<char> rawbuff;
    m_freader.read(rawbuff, size);
    vector<char> decbuff;
    if(decrypterUsed) {
        // initiate ctx
        EVP_CIPHER_CTX *ctx = nullptr;
        decbuff.resize(size + static_cast<fstream::pos_type>(32));
        int outlen1, outlen2;
        if ((ctx = EVP_CIPHER_CTX_new()) == nullptr
                || EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, reinterpret_cast<unsigned const char *>(m_password), iv) != 1
                || EVP_DecryptUpdate(ctx, reinterpret_cast<unsigned char *>(decbuff.data()), &outlen1, reinterpret_cast<unsigned char *>(rawbuff.data()), size) != 1
                || EVP_DecryptFinal_ex(ctx, reinterpret_cast<unsigned char *>(decbuff.data()) + outlen1, &outlen2) != 1) {
            if(ctx) {
                EVP_CIPHER_CTX_free(ctx);
            }
            string msg;
            unsigned long errorCode = ERR_get_error();
            while(errorCode != 0) {
                if(!msg.empty()) {
                    msg += "\n";
                }
                msg += ERR_error_string(errorCode, 0);
                errorCode = ERR_get_error();
            }
            throw CryptoException(msg);
        } else { // decryption suceeded
            if(ctx) {
                EVP_CIPHER_CTX_free(ctx);
            }
            size = outlen1 + outlen2;
        }
    } else { // file is not crypted
        decbuff.swap(rawbuff);
    }
    // decompress
    if(compressionUsed) {
        if(size < 8) {
            throw ParsingException("File is truncated (decompressed size expected).");
        }
        uLongf decompressedSize = ConversionUtilities::LE::toUInt64(decbuff.data());
        rawbuff.resize(decompressedSize);
        switch(uncompress(reinterpret_cast<Bytef *>(rawbuff.data()), &decompressedSize, reinterpret_cast<Bytef *>(decbuff.data() + 8), size - static_cast<fstream::pos_type>(8))) {
        case Z_MEM_ERROR:
            throw ParsingException("Decompressing failed. The source buffer was too small.");
        case Z_BUF_ERROR:
            throw ParsingException("Decompressing failed. The destination buffer was too small.");
        case Z_DATA_ERROR:
            throw ParsingException("Decompressing failed. The input data was corrupted or incomplete.");
        case Z_OK:
            decbuff.swap(rawbuff); // decompression successful
            size = decompressedSize;
        }
    }
    // parse contents
    stringstream buffstr(stringstream::in | stringstream::out | stringstream::binary);
    buffstr.write(decbuff.data(), static_cast<streamsize>(size));
    decbuff.resize(0);
    buffstr.seekg(0, ios_base::beg);
    m_rootEntry.reset(new NodeEntry(buffstr));
}

/*!
 * \brief Writes the current root entry to the file.
 * \param useEncryption Specifies whether encryption should be used.
 * \throws Throws ios_base::failure when an IO error occurs.
 * \throws Throws runtime_error when no root entry is present.
 * \throws Throws Io::CryptoException when a decryption error occurs.
 */
void PasswordFile::save(bool useEncryption, bool useCompression)
{
    if(!m_rootEntry) {
        throw runtime_error("Root entry has not been created.");
    }
    // open file
    if(m_file.is_open()) {
        m_file.close();
        m_file.clear();
    }
    m_file.open(m_path, ios_base::in | ios_base::out | ios_base::trunc | ios_base::binary);
    // write header
    m_fwriter.writeUInt32LE(0x7770616DU); // write magic number
    //m_fwriter.writeUInt32(useEncryption ? 2U : 0U); // write version (old versions)
    m_fwriter.writeUInt32LE(0x3U); // write version
    byte flags = 0x00;
    if(useEncryption) {
        flags |= 0x80 | 0x40;
    }
    if(useCompression) {
        flags |= 0x20;
    }
    m_fwriter.writeByte(flags);
    // serialize root entry and descendants
    stringstream buffstr(stringstream::in | stringstream::out | stringstream::binary);
    buffstr.exceptions(ios_base::failbit | ios_base::badbit);
    m_rootEntry->make(buffstr);
    buffstr.seekp(0, ios_base::end);
    stringstream::pos_type size = buffstr.tellp();
    // write the data to a buffer
    buffstr.seekg(0);
    vector<char> decbuff(size, 0);
    buffstr.read(decbuff.data(), size);
    vector<char> encbuff;
    // compress data
    if(useCompression) {
        uLongf compressedSize = compressBound(size);
        encbuff.resize(8 + compressedSize);
        ConversionUtilities::LE::getBytes(static_cast<uint64>(size), encbuff.data());
        switch(compress(reinterpret_cast<Bytef *>(encbuff.data() + 8), &compressedSize, reinterpret_cast<Bytef *>(decbuff.data()), size)) {
        case Z_MEM_ERROR:
            throw runtime_error("Decompressing failed. The source buffer was too small.");
        case Z_BUF_ERROR:
            throw runtime_error("Decompressing failed. The destination buffer was too small.");
        case Z_OK:
            encbuff.swap(decbuff); // decompression successful
            size = 8 + compressedSize;
        }
    }
    // encrypt data
    if(useEncryption) {
        // initiate ctx
        EVP_CIPHER_CTX *ctx = nullptr;
        unsigned char iv[aes256cbcIvSize];
        int outlen1, outlen2;
        encbuff.resize(size + static_cast<fstream::pos_type>(32));
        if (RAND_bytes(iv, aes256cbcIvSize) != 1
                || (ctx = EVP_CIPHER_CTX_new()) == nullptr
                || EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, reinterpret_cast<unsigned const char *>(m_password), iv) != 1
                || EVP_EncryptUpdate(ctx, reinterpret_cast<unsigned char *>(encbuff.data()), &outlen1, reinterpret_cast<unsigned char *>(decbuff.data()), size) != 1
                || EVP_EncryptFinal_ex(ctx, reinterpret_cast<unsigned char *>(encbuff.data()) + outlen1, &outlen2) != 1) {
            if(ctx) {
                EVP_CIPHER_CTX_free(ctx);
            }
            string msg;
            unsigned long errorCode = ERR_get_error();
            while(errorCode != 0) {
                if(!msg.empty()) {
                    msg += "\n";
                }
                msg += ERR_error_string(errorCode, 0);
                errorCode = ERR_get_error();
            }
            throw CryptoException(msg);
        } else { // decryption succeeded
            if(ctx) {
                EVP_CIPHER_CTX_free(ctx);
            }
            // write encrypted data to file
            m_file.write(reinterpret_cast<char *>(iv), aes256cbcIvSize);
            m_file.write(encbuff.data(), static_cast<streamsize>(outlen1 + outlen2));
        }
    } else {
        // write data to file
        m_file.write(decbuff.data(), static_cast<streamsize>(size));
    }
    m_file.flush();
}

/*!
 * \brief Removes the root element if one is present.
 */
void PasswordFile::clearEntries()
{
    m_rootEntry.reset();
}

/*!
 * \brief Closes the file if opened. Removes path, password and entries.
 */
void PasswordFile::clear()
{
    close();
    clearPath();
    clearPassword();
    clearEntries();
}

/*!
 * \brief Writes the current root entry to a plain text file. No encryption is used.
 * \param targetPath Specifies the path of the text file.
 * \throws Throws ios_base::failure when an IO error occurs.
 * \throws Throws runtime_error when no root entry is present.
 */
void PasswordFile::exportToTextfile(const string &targetPath) const
{
    if(!m_rootEntry) {
        throw runtime_error("Root entry has not been created.");
    }
    fstream output(targetPath.c_str(), ios_base::out);
    function<void (int level)> indention = [&output] (int level) {
        for(int i = 0; i < level; ++i) {
            output << "    ";
        }
    };
    function<void (const Entry *entry, int level)> printNode;
    printNode = [&output, &printNode, &indention] (const Entry *entry, int level) {
        indention(level);
        output << " - " << entry->label() << endl;
        switch(entry->type()) {
        case EntryType::Node:
            for(const Entry *child : static_cast<const NodeEntry *>(entry)->children()) {
                printNode(child, level + 1);
            }
            break;
        case EntryType::Account:
            for(const Field &field : static_cast<const AccountEntry *>(entry)->fields()) {
                indention(level);
                output << "    " << field.name();
                for(int i = field.name().length(); i < 15; ++i) {
                    output << ' ';
                }
                output << field.value() << endl;
            }
        }
    };
    printNode(m_rootEntry.get(), 0);
    output.close();
}

/*!
 * \brief Creates a backup of the file. Replaces an existent backup file.
 * \throws Throws ios_base::failure when an IO error occurs.
 */
void PasswordFile::doBackup()
{
    if(!isOpen()) {
        open();
    }
    fstream backupFile(m_path + ".backup", ios::out | ios::binary);
    backupFile.exceptions(ios_base::failbit | ios_base::badbit);
    m_file.seekg(0);
    backupFile << m_file.rdbuf();
    backupFile.close();
}

/*!
 * \brief Returns an indication whether a root entry is present.
 * \sa generateRootEntry()
 * \sa rootEntry()
 */
bool PasswordFile::hasRootEntry() const
{
    return m_rootEntry != nullptr;
}

/*!
 * \brief Returns the root entry if present or nullptr otherwise.
 */
const NodeEntry *PasswordFile::rootEntry() const
{
    return m_rootEntry.get();
}

/*!
 * \brief Returns the root entry if present or nullptr otherwise.
 */
NodeEntry *PasswordFile::rootEntry()
{
    return m_rootEntry.get();
}

/*!
 * \brief Closes the file if currently opened.
 */
void PasswordFile::close()
{
    if(m_file.is_open()) {
        m_file.close();
    }
    m_file.clear();
}

/*!
 * \brief Returns the current file path.
 */
const string &PasswordFile::path() const
{
    return m_path;
}

/*!
 * \brief Sets the current file path. Causes the file to be closed if currently opened.
 */
void PasswordFile::setPath(const string &value)
{
    close();
    m_path = value;
}

/*!
 * \brief Clears the current path. Causes the file to be closed if currently opened.
 */
void PasswordFile::clearPath()
{
    close();
    m_path.clear();
}

/*!
 * \brief Returns the current password. It will be used when loading or saving using encryption.
 */
const char *PasswordFile::password() const
{
    return m_password;
}

/*!
 * \brief Sets the current password. It will be used when loading or saving using encryption.
 */
void PasswordFile::setPassword(const string &value)
{
    clearPassword();
    value.copy(m_password, 32, 0);
}

/*!
 * \brief Clears the current password.
 */
void PasswordFile::clearPassword()
{
    memset(m_password, 0, 32);
}

/*!
 * \brief Returns an indication whether encryption is used if the file is open; returns always false otherwise.
 */
bool PasswordFile::isEncryptionUsed()
{
    if(!isOpen()) {
        return false;
    }
    m_file.seekg(0);
    //check magic number
    if(m_freader.readUInt32LE() != 0x7770616DU) {
        return false;
    }
    //check version
    uint32 version = m_freader.readUInt32LE();
    if(version == 0x1U || version == 0x2U) {
        return true;
    } else if(version == 0x3U) {
        return m_freader.readByte() & 0x80;
    } else {
        return false;
    }
}

/*!
 * \brief Returns an indication whether the file is open.
 */
bool PasswordFile::isOpen() const
{
    return m_file.is_open();
}

/*!
 * \brief Returns the size of the file if the file is open; returns always zero otherwise.
 */
size_t PasswordFile::size()
{
    if(!isOpen()) {
        return 0;
    }
    m_file.seekg(0, ios::end);
    return m_file.tellg();
}

}
