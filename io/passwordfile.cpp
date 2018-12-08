#include "./passwordfile.h"
#include "./cryptoexception.h"
#include "./entry.h"
#include "./parsingexception.h"

#include <c++utilities/conversion/stringbuilder.h>
#include <c++utilities/conversion/stringconversion.h>
#include <c++utilities/io/catchiofailure.h>

#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <zlib.h>

#include <cstring>
#include <functional>
#include <limits>
#include <memory>
#include <sstream>
#include <streambuf>

using namespace std;
using namespace ConversionUtilities;
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
PasswordFile::PasswordFile()
    : m_freader(BinaryReader(&m_file))
    , m_fwriter(BinaryWriter(&m_file))
{
    m_file.exceptions(ios_base::failbit | ios_base::badbit);
    clearPassword();
}

/*!
 * \brief Constructs a new password file with the specified \a path and \a password.
 */
PasswordFile::PasswordFile(const string &path, const string &password)
    : m_freader(BinaryReader(&m_file))
    , m_fwriter(BinaryWriter(&m_file))
{
    m_file.exceptions(ios_base::failbit | ios_base::badbit);
    setPath(path);
    setPassword(password);
}

/*!
 * \brief Constructs a copy of another password file.
 */
PasswordFile::PasswordFile(const PasswordFile &other)
    : m_path(other.m_path)
    , m_rootEntry(other.m_rootEntry ? make_unique<NodeEntry>(*other.m_rootEntry) : nullptr)
    , m_extendedHeader(other.m_extendedHeader)
    , m_encryptedExtendedHeader(other.m_encryptedExtendedHeader)
    , m_freader(BinaryReader(&m_file))
    , m_fwriter(BinaryWriter(&m_file))
{
    m_file.exceptions(ios_base::failbit | ios_base::badbit);
    memcpy(m_password, other.m_password, 32);
}

/*!
 * \brief Moves the password file.
 */
PasswordFile::PasswordFile(PasswordFile &&other)
    : m_path(move(other.m_path))
    , m_rootEntry(move(other.m_rootEntry))
    , m_extendedHeader(move(other.m_extendedHeader))
    , m_encryptedExtendedHeader(move(other.m_encryptedExtendedHeader))
    , m_file(move(other.m_file))
    , m_freader(BinaryReader(&m_file))
    , m_fwriter(BinaryWriter(&m_file))
{
    memcpy(m_password, other.m_password, 32);
}

/*!
 * \brief Closes the file if still opened and destroys the instance.
 */
PasswordFile::~PasswordFile()
{
}

/*!
 * \brief Opens the file. Does not load the contents (see load()).
 * \throws Throws ios_base::failure when an IO error occurs.
 */
void PasswordFile::open(bool readOnly)
{
    close();
    if (m_path.empty()) {
        throwIoFailure("Unable to open file because path is emtpy.");
    }
    m_file.open(m_path, readOnly ? ios_base::in | ios_base::binary : ios_base::in | ios_base::out | ios_base::binary);
    opened();
}

/*!
 * \brief Handles the file being opened.
 *
 * Call this method after opening a file directly via the underlying fileStream().
 */
void PasswordFile::opened()
{
    m_file.seekg(0, ios_base::end);
    if (m_file.tellg() == 0) {
        throwIoFailure("File is empty.");
    } else {
        m_file.seekg(0);
    }
}

/*!
 * \brief Generates a new root entry for the file.
 */
void PasswordFile::generateRootEntry()
{
    if (!m_rootEntry) {
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
    if (m_path.empty()) {
        throwIoFailure("Unable to create file because path is empty.");
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
    if (!m_file.is_open()) {
        open();
    }
    m_file.seekg(0);

    // check magic number
    if (m_freader.readUInt32LE() != 0x7770616DU) {
        throw ParsingException("Signature not present.");
    }

    // check version and flags (used in version 0x3 only)
    const auto version = m_freader.readUInt32LE();
    if (version != 0x0U && version != 0x1U && version != 0x2U && version != 0x3U && version != 0x4U && version != 0x5U) {
        throw ParsingException("Version is unknown.");
    }
    bool decrypterUsed, ivUsed, compressionUsed;
    if (version == 0x3U) {
        const auto flags = m_freader.readByte();
        decrypterUsed = flags & 0x80;
        ivUsed = flags & 0x40;
        compressionUsed = flags & 0x20;
    } else {
        decrypterUsed = version >= 0x1U;
        ivUsed = version == 0x2U;
        compressionUsed = false;
    }

    // skip extended header
    // (the extended header might be used in further versions to
    //  add additional information without breaking compatibility)
    if (version >= 0x4U) {
        uint16 extendedHeaderSize = m_freader.readUInt16BE();
        m_extendedHeader = m_freader.readString(extendedHeaderSize);
    }

    // get length
    const auto headerSize = static_cast<size_t>(m_file.tellg());
    m_file.seekg(0, ios_base::end);
    auto remainingSize = static_cast<size_t>(m_file.tellg()) - headerSize;
    m_file.seekg(static_cast<streamoff>(headerSize), ios_base::beg);

    // read file
    unsigned char iv[aes256cbcIvSize] = { 0 };
    if (decrypterUsed && ivUsed) {
        if (remainingSize < aes256cbcIvSize) {
            throw ParsingException("Initiation vector is truncated.");
        }
        m_file.read(reinterpret_cast<char *>(iv), aes256cbcIvSize);
        remainingSize -= aes256cbcIvSize;
    }
    if (!remainingSize) {
        throw ParsingException("No contents found.");
    }

    // decrypt contents
    vector<char> rawData;
    m_freader.read(rawData, static_cast<streamoff>(remainingSize));
    vector<char> decryptedData;
    if (decrypterUsed) {
        if (remainingSize > numeric_limits<int>::max()) {
            throw CryptoException("Size exceeds limit.");
        }

        // initiate ctx, decrypt data
        EVP_CIPHER_CTX *ctx = nullptr;
        decryptedData.resize(remainingSize + 32);
        int outlen1, outlen2;
        if ((ctx = EVP_CIPHER_CTX_new()) == nullptr
            || EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, reinterpret_cast<unsigned const char *>(m_password), iv) != 1
            || EVP_DecryptUpdate(ctx, reinterpret_cast<unsigned char *>(decryptedData.data()), &outlen1,
                   reinterpret_cast<unsigned char *>(rawData.data()), static_cast<int>(remainingSize))
                != 1
            || EVP_DecryptFinal_ex(ctx, reinterpret_cast<unsigned char *>(decryptedData.data()) + outlen1, &outlen2) != 1) {
            // handle decryption error
            if (ctx) {
                EVP_CIPHER_CTX_free(ctx);
            }
            string msg;
            auto errorCode = ERR_get_error();
            while (errorCode) {
                if (!msg.empty()) {
                    msg += "\n";
                }
                msg += ERR_error_string(errorCode, nullptr);
                errorCode = ERR_get_error();
            }
            throw CryptoException(msg);
        }

        if (ctx) {
            EVP_CIPHER_CTX_free(ctx);
        }
        const auto decryptedSize = outlen1 + outlen2;
        if (decryptedSize < 0) {
            throw CryptoException("Decrypted size is negative.");
        }
        remainingSize = static_cast<size_t>(decryptedSize);
        if (!remainingSize) {
            throw ParsingException("Decrypted buffer is empty.");
        }

    } else {
        // use raw data directly if not encrypted
        decryptedData.swap(rawData);
    }

    // decompress
    if (compressionUsed) {
        if (remainingSize < 8) {
            throw ParsingException("File is truncated (decompressed size expected).");
        }
        uLongf decompressedSize = ConversionUtilities::LE::toUInt64(decryptedData.data());
        rawData.resize(decompressedSize);
        switch (uncompress(
            reinterpret_cast<Bytef *>(rawData.data()), &decompressedSize, reinterpret_cast<Bytef *>(decryptedData.data() + 8), remainingSize - 8)) {
        case Z_MEM_ERROR:
            throw ParsingException("Decompressing failed. The source buffer was too small.");
        case Z_BUF_ERROR:
            throw ParsingException("Decompressing failed. The destination buffer was too small.");
        case Z_DATA_ERROR:
            throw ParsingException("Decompressing failed. The input data was corrupted or incomplete.");
        case Z_OK:
            decryptedData.swap(rawData);
            remainingSize = decompressedSize;
        }
    }
    if (!remainingSize) {
        throw ParsingException("Decompressed buffer is empty.");
    }

    // parse contents
    stringstream decryptedStream(stringstream::in | stringstream::out | stringstream::binary);
    decryptedStream.exceptions(ios_base::failbit | ios_base::badbit);
    try {
#ifdef _LIBCPP_VERSION
        decryptedStream.write(decryptedData.data(), static_cast<streamsize>(remainingSize));
#else
        decryptedStream.rdbuf()->pubsetbuf(decryptedData.data(), static_cast<streamsize>(remainingSize));
#endif
        if (version >= 0x5u) {
            const auto extendedHeaderSize = m_freader.readUInt16BE();
            m_encryptedExtendedHeader = m_freader.readString(extendedHeaderSize);
        }
        m_rootEntry.reset(new NodeEntry(decryptedStream));
    } catch (...) {
        const char *const what = catchIoFailure();
        if (decryptedStream.eof()) {
            throw ParsingException("The file seems to be truncated.");
        }
        throw ParsingException(argsToString("An IO error occurred when reading internal buffer: ", what));
    }
}

/*!
 * \brief Writes the current root entry to the file under path() replacing its previous contents.
 * \param useEncryption Specifies whether encryption should be used.
 * \param useCompression Specifies whether compression should be used.
 * \throws Throws ios_base::failure when an IO error occurs.
 * \throws Throws runtime_error when no root entry is present or a compression error occurs.
 * \throws Throws Io::CryptoException when an encryption error occurs.
 */
void PasswordFile::save(bool useEncryption, bool useCompression)
{
    if (!m_rootEntry) {
        throw runtime_error("Root entry has not been created.");
    }

    // use already opened and writable file; otherwise re-open the file
    if (m_file.good() && m_file.is_open() && (m_file.flags() & ios_base::out)) {
        m_file.seekp(0);
    } else {
        m_file.close();
        m_file.clear();
        m_file.open(m_path, ios_base::in | ios_base::out | ios_base::trunc | ios_base::binary);
    }

    write(useEncryption, useCompression);
    m_file.flush();
}

/*!
 * \brief Writes the current root entry to the file which is assumed to be opened and writeable.
 * \param useEncryption Specifies whether encryption should be used.
 * \param useCompression Specifies whether compression should be used.
 * \throws Throws ios_base::failure when an IO error occurs.
 * \throws Throws runtime_error when no root entry is present or a compression error occurs.
 * \throws Throws Io::CryptoException when an encryption error occurs.
 */
void PasswordFile::write(bool useEncryption, bool useCompression)
{
    if (!m_rootEntry) {
        throw runtime_error("Root entry has not been created.");
    }

    // write magic number
    m_fwriter.writeUInt32LE(0x7770616DU);

    // write version, extended header requires version 4, encrypted extended header required version 5
    m_fwriter.writeUInt32LE(m_extendedHeader.empty() && m_encryptedExtendedHeader.empty() ? 0x3U : (m_encryptedExtendedHeader.empty() ? 0x4U : 0x5U));
    byte flags = 0x00;
    if (useEncryption) {
        flags |= 0x80 | 0x40;
    }
    if (useCompression) {
        flags |= 0x20;
    }
    m_fwriter.writeByte(flags);

    // write extened header
    if (!m_extendedHeader.empty()) {
        m_fwriter.writeUInt16BE(static_cast<uint16>(m_extendedHeader.size()));
        m_fwriter.writeString(m_extendedHeader);
    }

    // serialize root entry and descendants
    stringstream buffstr(stringstream::in | stringstream::out | stringstream::binary);
    buffstr.exceptions(ios_base::failbit | ios_base::badbit);

    // write encrypted extened header
    if (!m_encryptedExtendedHeader.empty()) {
        m_fwriter.writeUInt16BE(static_cast<uint16>(m_encryptedExtendedHeader.size()));
        m_fwriter.writeString(m_encryptedExtendedHeader);
    }
    m_rootEntry->make(buffstr);
    buffstr.seekp(0, ios_base::end);
    auto size = static_cast<size_t>(buffstr.tellp());

    // write the data to a buffer
    buffstr.seekg(0);
    vector<char> decryptedData(size, 0);
    buffstr.read(decryptedData.data(), static_cast<streamoff>(size));
    vector<char> encryptedData;

    // compress data
    if (useCompression) {
        uLongf compressedSize = compressBound(size);
        encryptedData.resize(8 + compressedSize);
        ConversionUtilities::LE::getBytes(static_cast<uint64>(size), encryptedData.data());
        switch (
            compress(reinterpret_cast<Bytef *>(encryptedData.data() + 8), &compressedSize, reinterpret_cast<Bytef *>(decryptedData.data()), size)) {
        case Z_MEM_ERROR:
            throw runtime_error("Compressing failed. The source buffer was too small.");
        case Z_BUF_ERROR:
            throw runtime_error("Compressing failed. The destination buffer was too small.");
        case Z_OK:
            encryptedData.swap(decryptedData); // decompression successful
            size = 8 + compressedSize;
        }
    }

    if (size > numeric_limits<int>::max()) {
        throw CryptoException("size exceeds limit");
    }

    // write data without encryption
    if (!useEncryption) {
        // write data to file
        m_file.write(decryptedData.data(), static_cast<streamsize>(size));
        return;
    }

    // initiate ctx, encrypt data
    EVP_CIPHER_CTX *ctx = nullptr;
    unsigned char iv[aes256cbcIvSize];
    int outlen1, outlen2;
    encryptedData.resize(size + 32);
    if (RAND_bytes(iv, aes256cbcIvSize) != 1 || (ctx = EVP_CIPHER_CTX_new()) == nullptr
        || EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, reinterpret_cast<unsigned const char *>(m_password), iv) != 1
        || EVP_EncryptUpdate(ctx, reinterpret_cast<unsigned char *>(encryptedData.data()), &outlen1,
               reinterpret_cast<unsigned char *>(decryptedData.data()), static_cast<int>(size))
            != 1
        || EVP_EncryptFinal_ex(ctx, reinterpret_cast<unsigned char *>(encryptedData.data()) + outlen1, &outlen2) != 1) {
        // handle encryption error
        if (ctx) {
            EVP_CIPHER_CTX_free(ctx);
        }
        string msg;
        auto errorCode = ERR_get_error();
        while (errorCode) {
            if (!msg.empty()) {
                msg += "\n";
            }
            msg += ERR_error_string(errorCode, nullptr);
            errorCode = ERR_get_error();
        }
        throw CryptoException(msg);
    }

    if (ctx) {
        EVP_CIPHER_CTX_free(ctx);
    }

    // write encrypted data to file
    m_file.write(reinterpret_cast<char *>(iv), aes256cbcIvSize);
    m_file.write(encryptedData.data(), static_cast<streamsize>(outlen1 + outlen2));
}

/*!
 * \brief Removes the root element if one is present.
 */
void PasswordFile::clearEntries()
{
    m_rootEntry.reset();
}

/*!
 * \brief Closes the file if opened. Removes path, password and entries and additional information.
 */
void PasswordFile::clear()
{
    close();
    clearPath();
    clearPassword();
    clearEntries();
    m_extendedHeader.clear();
    m_encryptedExtendedHeader.clear();
}

/*!
 * \brief Writes the current root entry to a plain text file. No encryption is used.
 * \param targetPath Specifies the path of the text file.
 * \throws Throws ios_base::failure when an IO error occurs.
 * \throws Throws runtime_error when no root entry is present.
 */
void PasswordFile::exportToTextfile(const string &targetPath) const
{
    if (!m_rootEntry) {
        throw runtime_error("Root entry has not been created.");
    }
    fstream output(targetPath.c_str(), ios_base::out);
    const auto printIndention = [&output](int level) {
        for (int i = 0; i < level; ++i) {
            output << "    ";
        }
    };
    function<void(const Entry *entry, int level)> printNode;
    printNode = [&output, &printNode, &printIndention](const Entry *entry, int level) {
        printIndention(level);
        output << " - " << entry->label() << endl;
        switch (entry->type()) {
        case EntryType::Node:
            for (const Entry *child : static_cast<const NodeEntry *>(entry)->children()) {
                printNode(child, level + 1);
            }
            break;
        case EntryType::Account:
            for (const Field &field : static_cast<const AccountEntry *>(entry)->fields()) {
                printIndention(level);
                output << "    " << field.name();
                for (auto i = field.name().length(); i < 15; ++i) {
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
    if (!isOpen()) {
        open();
    }

    // skip if the current file is empty anyways
    if (!size()) {
        return;
    }

    m_file.seekg(0);
    fstream backupFile(m_path + ".backup", ios::out | ios::trunc | ios::binary);
    backupFile.exceptions(ios_base::failbit | ios_base::badbit);
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
    if (m_file.is_open()) {
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
 * \brief Sets the current file path. Closes the file if currently opened.
 */
void PasswordFile::setPath(const string &value)
{
    close();
    m_path = value;

    // support "file://" protocol
    if (ConversionUtilities::startsWith(m_path, "file:")) {
        m_path = m_path.substr(5);
    }
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
    if (!isOpen()) {
        return false;
    }
    m_file.seekg(0);

    //check magic number
    if (m_freader.readUInt32LE() != 0x7770616DU) {
        return false;
    }

    //check version
    const auto version = m_freader.readUInt32LE();
    if (version == 0x1U || version == 0x2U) {
        return true;
    } else if (version == 0x3U) {
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
 * \brief Returns the size of the file if the file is open; otherwise returns zero.
 */
size_t PasswordFile::size()
{
    if (!isOpen()) {
        return 0;
    }
    m_file.seekg(0, ios::end);
    return static_cast<size_t>(m_file.tellg());
}
} // namespace Io
