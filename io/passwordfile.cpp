#include "./passwordfile.h"
#include "./cryptoexception.h"
#include "./entry.h"
#include "./parsingexception.h"

#include "../util/openssl.h"
#include "../util/opensslrandomdevice.h"

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
    , m_version(0)
    , m_openOptions(PasswordFileOpenFlags::None)
    , m_saveOptions(PasswordFileSaveFlags::None)
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
    , m_version(0)
    , m_openOptions(PasswordFileOpenFlags::None)
    , m_saveOptions(PasswordFileSaveFlags::None)
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
    , m_password(other.m_password)
    , m_rootEntry(other.m_rootEntry ? make_unique<NodeEntry>(*other.m_rootEntry) : nullptr)
    , m_extendedHeader(other.m_extendedHeader)
    , m_encryptedExtendedHeader(other.m_encryptedExtendedHeader)
    , m_freader(BinaryReader(&m_file))
    , m_fwriter(BinaryWriter(&m_file))
    , m_version(other.m_version)
    , m_openOptions(other.m_openOptions)
    , m_saveOptions(other.m_saveOptions)
{
    m_file.exceptions(ios_base::failbit | ios_base::badbit);
}

/*!
 * \brief Moves the password file.
 */
PasswordFile::PasswordFile(PasswordFile &&other)
    : m_path(move(other.m_path))
    , m_password(move(other.m_password))
    , m_rootEntry(move(other.m_rootEntry))
    , m_extendedHeader(move(other.m_extendedHeader))
    , m_encryptedExtendedHeader(move(other.m_encryptedExtendedHeader))
    , m_file(move(other.m_file))
    , m_freader(BinaryReader(&m_file))
    , m_fwriter(BinaryWriter(&m_file))
    , m_version(other.m_version)
    , m_openOptions(other.m_openOptions)
    , m_saveOptions(other.m_saveOptions)
{
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
void PasswordFile::open(PasswordFileOpenFlags options)
{
    close();
    if (m_path.empty()) {
        throwIoFailure("Unable to open file because path is emtpy.");
    }
    m_file.open(
        m_path, options & PasswordFileOpenFlags::ReadOnly ? ios_base::in | ios_base::binary : ios_base::in | ios_base::out | ios_base::binary);
    m_openOptions = options;
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
    m_version = 0;
    m_saveOptions = PasswordFileSaveFlags::None;

    // check magic number
    if (m_freader.readUInt32LE() != 0x7770616DU) {
        throw ParsingException("Signature not present.");
    }

    // check version and flags (used in version 0x3 only)
    m_version = m_freader.readUInt32LE();
    if (m_version > 0x6U) {
        throw ParsingException(argsToString("Version \"", m_version, "\" is unknown. Only versions 0 to 6 are supported."));
    }
    if (m_version >= 0x6U) {
        m_saveOptions |= PasswordFileSaveFlags::PasswordHashing;
    }
    bool decrypterUsed, ivUsed, compressionUsed;
    if (m_version >= 0x3U) {
        const auto flags = m_freader.readByte();
        if ((decrypterUsed = flags & 0x80)) {
            m_saveOptions |= PasswordFileSaveFlags::Encryption;
        }
        if ((compressionUsed = flags & 0x20)) {
            m_saveOptions |= PasswordFileSaveFlags::Compression;
        }
        ivUsed = flags & 0x40;
    } else {
        if ((decrypterUsed = m_version >= 0x1U)) {
            m_saveOptions |= PasswordFileSaveFlags::Encryption;
        }
        compressionUsed = false;
        ivUsed = m_version == 0x2U;
    }

    // skip extended header
    // (the extended header might be used in further versions to
    //  add additional information without breaking compatibility)
    if (m_version >= 0x4U) {
        uint16 extendedHeaderSize = m_freader.readUInt16BE();
        m_extendedHeader = m_freader.readString(extendedHeaderSize);
    } else {
        m_extendedHeader.clear();
    }

    // get length
    const auto headerSize = static_cast<size_t>(m_file.tellg());
    m_file.seekg(0, ios_base::end);
    auto remainingSize = static_cast<size_t>(m_file.tellg()) - headerSize;
    m_file.seekg(static_cast<streamoff>(headerSize), ios_base::beg);

    // read hash count
    uint32_t hashCount = 0U;
    if ((m_saveOptions & PasswordFileSaveFlags::PasswordHashing) && decrypterUsed) {
        if (remainingSize < 4) {
            throw ParsingException("Hash count truncated.");
        }
        hashCount = m_freader.readUInt32BE();
        remainingSize -= 4;
    }

    // read IV
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

        // prepare password
        Util::OpenSsl::Sha256Sum password;
        if (hashCount) {
            // hash the password as often as it has been hashed when writing the file
            password = Util::OpenSsl::computeSha256Sum(reinterpret_cast<unsigned const char *>(m_password.data()), m_password.size());
            for (uint32_t i = 1; i < hashCount; ++i) {
                password = Util::OpenSsl::computeSha256Sum(password.data, Util::OpenSsl::Sha256Sum::size);
            }
        } else {
            m_password.copy(reinterpret_cast<char *>(password.data), Util::OpenSsl::Sha256Sum::size);
        }

        // initiate ctx, decrypt data
        EVP_CIPHER_CTX *ctx = nullptr;
        decryptedData.resize(remainingSize + 32);
        int outlen1, outlen2;
        if ((ctx = EVP_CIPHER_CTX_new()) == nullptr || EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, password.data, iv) != 1
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
            throw CryptoException(move(msg));
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
        if (remainingSize > numeric_limits<uLongf>::max()) {
            throw CryptoException("Size exceeds limit.");
        }
        const auto rawDecompressedSize = ConversionUtilities::LE::toUInt64(decryptedData.data());
        if (rawDecompressedSize > numeric_limits<uLongf>::max()) {
            throw ParsingException("Decompressed size exceeds limit.");
        }
        auto decompressedSize = static_cast<uLongf>(rawDecompressedSize);
        rawData.resize(decompressedSize);
        switch (uncompress(reinterpret_cast<Bytef *>(rawData.data()), &decompressedSize, reinterpret_cast<Bytef *>(decryptedData.data() + 8),
            static_cast<uLongf>(remainingSize - 8))) {
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
        if (m_version >= 0x5u) {
            BinaryReader reader(&decryptedStream);
            const auto extendedHeaderSize = reader.readUInt16BE();
            m_encryptedExtendedHeader = reader.readString(extendedHeaderSize);
        } else {
            m_encryptedExtendedHeader.clear();
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
 * \brief Returns the minimum file version required to write the current instance with the specified \a options.
 * \remarks This version will be used by save() and write() when passing the same \a options.
 */
uint32 PasswordFile::mininumVersion(PasswordFileSaveFlags options) const
{
    if (options & PasswordFileSaveFlags::PasswordHashing) {
        return 0x6U; // password hashing requires at least version 6
    } else if (!m_encryptedExtendedHeader.empty()) {
        return 0x5U; // encrypted extended header requires at least version 5
    } else if (!m_extendedHeader.empty()) {
        return 0x4U; // regular extended header requires at least version 4
    }
    return 0x3U; // lowest supported version by the serializer
}

/*!
 * \brief Writes the current root entry to the file under path() replacing its previous contents.
 * \param options Specify the features (like encryption and compression) to be used.
 * \throws Throws ios_base::failure when an IO error occurs.
 * \throws Throws runtime_error when no root entry is present or a compression error occurs.
 * \throws Throws Io::CryptoException when an encryption error occurs.
 */
void PasswordFile::save(PasswordFileSaveFlags options)
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

    write(options);
    m_file.flush();
}

/*!
 * \brief Writes the current root entry to the file which is assumed to be opened and writeable.
 * \param options Specify the features (like encryption and compression) to be used.
 * \throws Throws ios_base::failure when an IO error occurs.
 * \throws Throws runtime_error when no root entry is present or a compression error occurs.
 * \throws Throws Io::CryptoException when an encryption error occurs.
 */
void PasswordFile::write(PasswordFileSaveFlags options)
{
    if (!m_rootEntry) {
        throw runtime_error("Root entry has not been created.");
    }

    // write magic number
    m_fwriter.writeUInt32LE(0x7770616DU);

    // write version
    const auto version = mininumVersion(options);
    m_fwriter.writeUInt32LE(version);

    // write flags
    byte flags = 0x00;
    if (options & PasswordFileSaveFlags::Encryption) {
        flags |= 0x80 | 0x40;
    }
    if (options & PasswordFileSaveFlags::Compression) {
        flags |= 0x20;
    }
    m_fwriter.writeByte(flags);

    // write extened header
    if (version >= 0x4U) {
        if (m_extendedHeader.size() > numeric_limits<uint16>::max()) {
            throw runtime_error("Extended header exceeds maximum size.");
        }
        m_fwriter.writeUInt16BE(static_cast<uint16>(m_extendedHeader.size()));
        m_fwriter.writeString(m_extendedHeader);
    }

    // serialize root entry and descendants
    stringstream buffstr(stringstream::in | stringstream::out | stringstream::binary);
    buffstr.exceptions(ios_base::failbit | ios_base::badbit);

    // write encrypted extened header
    if (version >= 0x5U) {
        if (m_encryptedExtendedHeader.size() > numeric_limits<uint16>::max()) {
            throw runtime_error("Encrypted extended header exceeds maximum size.");
        }
        BinaryWriter buffstrWriter(&buffstr);
        buffstrWriter.writeUInt16BE(static_cast<uint16>(m_encryptedExtendedHeader.size()));
        buffstrWriter.writeString(m_encryptedExtendedHeader);
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
    if (options & PasswordFileSaveFlags::Compression) {
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
    if (!(options & PasswordFileSaveFlags::Encryption)) {
        // write data to file
        m_file.write(decryptedData.data(), static_cast<streamsize>(size));
        return;
    }

    // prepare password
    Util::OpenSsl::Sha256Sum password;
    const uint32_t hashCount = (options & PasswordFileSaveFlags::PasswordHashing) ? Util::OpenSsl::generateRandomNumber(1, 100) : 0u;
    if (hashCount) {
        // hash password a few times
        password = Util::OpenSsl::computeSha256Sum(reinterpret_cast<unsigned const char *>(m_password.data()), m_password.size());
        for (uint32_t i = 1; i < hashCount; ++i) {
            password = Util::OpenSsl::computeSha256Sum(password.data, Util::OpenSsl::Sha256Sum::size);
        }
    } else {
        m_password.copy(reinterpret_cast<char *>(password.data), Util::OpenSsl::Sha256Sum::size);
    }

    // initiate ctx, encrypt data
    EVP_CIPHER_CTX *ctx = nullptr;
    unsigned char iv[aes256cbcIvSize];
    int outlen1, outlen2;
    encryptedData.resize(size + 32);
    if (RAND_bytes(iv, aes256cbcIvSize) != 1 || (ctx = EVP_CIPHER_CTX_new()) == nullptr
        || EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, password.data, iv) != 1
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
        throw CryptoException(move(msg));
    }

    if (ctx) {
        EVP_CIPHER_CTX_free(ctx);
    }

    // write encrypted data to file
    if (version >= 0x6U) {
        m_fwriter.writeUInt32BE(hashCount);
    }
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
    m_openOptions = PasswordFileOpenFlags::None;
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
 * \brief Returns an indication whether encryption is used and the file is open; returns always false otherwise.
 * \remarks This method is meant to determine whether encryption is used *before* loading the file. If the file has
 *          already been loaded, use preferably saveOptions().
 */
bool PasswordFile::isEncryptionUsed()
{
    if (!isOpen()) {
        return false;
    }
    m_file.seekg(0);

    // check magic number
    if (m_freader.readUInt32LE() != 0x7770616DU) {
        return false;
    }

    // check version
    const auto version = m_freader.readUInt32LE();
    if (version == 0x1U || version == 0x2U) {
        return true;
    } else if (version >= 0x3U) {
        return m_freader.readByte() & 0x80;
    } else {
        return false;
    }
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

/*!
 * \brief Returns a summary about the file (version, used features, statistics).
 */
string PasswordFile::summary(PasswordFileSaveFlags saveOptions) const
{
    string result = "<table>";
    if (!m_path.empty()) {
        result += argsToString("<tr><td>Path:</td><td>", m_path, "</td></tr>");
    }
    result += argsToString("<tr><td>Version:</td><td>", m_version, "</td></tr>");
    const auto minVersion = mininumVersion(saveOptions);
    if (m_version != minVersion) {
        result += argsToString("<tr><td></td><td>(on disk, after saving: ", minVersion, ")</td></tr>");
    }
    result += argsToString("<tr><td>Features:</td><td>", flagsToString(m_saveOptions), "</td></tr>");
    if (m_saveOptions != saveOptions) {
        result += argsToString("<tr><td></td><td>(on disk, after saving: ", flagsToString(saveOptions), ")</td></tr>");
    }
    const auto stats = m_rootEntry ? m_rootEntry->computeStatistics() : EntryStatistics();
    result += argsToString("<tr><td>Number of categories:</td><td>", stats.nodeCount, "</td></tr><tr><td>Number of accounts:</td><td>",
        stats.accountCount, "</td></tr><tr><td>Number of fields:</td><td>", stats.fieldCount, "</td></tr></table>");
    return result;
}

/*!
 * \brief Returns a comma-separated string for the specified \a flags.
 */
string flagsToString(PasswordFileOpenFlags flags)
{
    vector<string> options;
    if (flags & PasswordFileOpenFlags::ReadOnly) {
        options.emplace_back("read-only");
    }
    if (options.empty()) {
        options.emplace_back("none");
    }
    return joinStrings(options, ", ");
}

/*!
 * \brief Returns a comma-separated string for the specified \a flags.
 */
string flagsToString(PasswordFileSaveFlags flags)
{
    vector<string> options;
    options.reserve(3);
    if (flags & PasswordFileSaveFlags::Encryption) {
        options.emplace_back("encryption");
    }
    if (flags & PasswordFileSaveFlags::Compression) {
        options.emplace_back("compression");
    }
    if (flags & PasswordFileSaveFlags::PasswordHashing) {
        options.emplace_back("password hashing");
    }
    if (options.empty()) {
        options.emplace_back("none");
    }
    return joinStrings(options, ", ");
}

} // namespace Io
