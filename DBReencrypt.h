/*
    Copyright (C) 2019-Present SKALE Labs

    This file is part of sgxwallet.

    sgxwallet is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as published
    by the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    sgxwallet is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with sgxwallet. If not, see <https://www.gnu.org/licenses/>.
*/

#ifndef SGXD_DBREENCRYPT_H
#define SGXD_DBREENCRYPT_H

#include <cstdint>
#include <string>
#include <string_view>

#include <json/value.h>

class DBReencryptorTests;

class DBReencryptor {
    friend class DBReencryptorTests;

public:
    /**
    * Reencrypts the wallet database with a newly generated SEK.
    *
    * The migration reads the current backup SEK, asks the enclave to begin a
    * reencryption session, writes a temporary DB with reencrypted payloads,
    * atomically swaps DB directories, commits the enclave session, and replaces
    * the backup SEK file.
    */
    void reencryptWithNewSEK();

private:
    static constexpr uint64_t DB_REENCRYPT_PAYLOAD_BUF_SIZE = 8192;
    static constexpr uint64_t SEALED_SEK_BUF_SIZE = 1024;

    struct NewSEK {
        // New SEK encrypted with the enclave key, in hex format.
        std::string sealedHex;
        // New SEK plaintext, in hex format, written to the backup SEK file.
        std::string plaintextHex;
    };

    /**
     * @brief Represents a parsed DB value, either in old-style (plaintext) or 
     * new-style format (json with timestamp).
     */
    struct ParsedDBValue {
        // True when the DB value is a JSON wrapper with "value" and "timestamp".
        bool newStyle = false;
        // Original parsed JSON value for new-style DB rows.
        Json::Value jsonValue;
        // Encrypted payload extracted from either old-style or new-style DB rows.
        std::string payload;
    };

    struct MigrationStats {
        // Number of DB records storing encrypted values (SEK row + encrypted payload rows).
        uint64_t encrypted = 0;
        // Number of DB records whose encrypted payload was reencrypted.
        uint64_t reencrypted = 0;
        // Number of DB records copied as-is because they are not encrypted payload rows.
        uint64_t plaintextCopied = 0;
        // Whether the old SEK row was found and replaced during migration.
        bool sawSEK = false;
        // Whether TEST_KEY was found and reencrypted during migration.
        bool sawTestKey = false;
    };

    struct DBSwapState {
        // Current wallet DB directory path.
        std::string sourcePath;
        // Temporary DB directory path containing migrated data.
        std::string temporaryPath;
        // Backup path for the original wallet DB directory.
        std::string backupPath;
        // True once the original DB was moved to the backup path.
        bool sourceMoved = false;
        // True once the temporary DB was moved into the source path.
        bool temporaryMoved = false;
    };

    class ReencryptVisitor;

    // ------------------------ Reencryption Process Steps ------------------------

    /** 1.
     * @brief Reads and validates the current plaintext backup SEK from disk. 
    */
    std::string readBackupSEK(const std::string_view& path) const;

    /** 2.
    * @brief Calls trustedBeginDBReencrypt - generates new SEK, seals it, and sets
    * tmp internal buffers with new and old SEK for use in subsequent steps.
    * This call uses lock to make sure only 1 reencryption process can be running 
    * at a time.
    * @throws SGXException if there is already a reencryption process running
    */
    NewSEK beginDBReencrypt(const std::string &oldSEKHex) const;

    /** 3. 
     * @brief Writes a temporary wallet DB containing copied and reencrypted 
     * records. 
     */
    MigrationStats writeReencryptedWalletDB(
        const std::string &temporaryDBPath,
        const std::string &newSealedSEKHex);

    /** 4.
     * @brief Rename original DB into backup path, and
     * rename temporary DB into original DB path
     */
    void swapWalletDB(DBSwapState &swapState) const;

    /** 5.a
     * @brief Commits the enclave-side reencryption session. Only gets called
     * if db reencryption was successful.
     * Sets internal encalve's SEK as the new SEK and clears tmp DB migration
     * buffers.
     * This call is protected by lock.
     */
    void commitDBReencrypt() const;

    /** 5.b
     * @brief Rolls back a partially completed DB directory.
     * Move tmp new DB to '<name>.failed' for debugging, and move
     * original DB to original path if it was moved to backup path. 
     * This call does not reollback secure enclave state.
     */
    void rollbackWalletDBSwapNoThrow(DBSwapState &swapState) const;


    // ------------------------- Helper Functions ------------------------

    /** 
     * Builds a unique suffix for temporary and backup migration paths using
     * process ID and current timestamp, to avoid conflicts with any recent
     * migrations 
     * @return A string containing the unique suffix.
     */
    std::string migrationSuffix() const;


    /** 
     * Writes the new plaintext SEK to the temporary backup SEK file.
     * @param sekHex The new SEK in plaintext hexadecimal format.
     * @param path The path to the temporary backup SEK file.
     */
    void writeBackupSEKTmp(std::string_view sekHex,
                            std::string_view path) const;

    /** Parses a raw DB value into payload plus optional JSON wrapper metadata. */
    ParsedDBValue parseDBValue(const std::string &rawValue) const;

    /** Encodes a reencrypted payload back into the original DB value format. */
    std::string encodeDBValue(const ParsedDBValue &parsed,
                            const std::string &payload) const;

    /** Returns true when the DB key stores a payload encrypted with the SEK. */
    bool isKeyHoldingEncryptedValue(std::string_view key) const;

    /** Returns true when value begins with prefix. */
    bool startsWith(std::string_view value, std::string_view prefix) const;

    /** Reencrypts one encrypted DB payload hex string through the enclave. */
    std::string
    reencryptEncryptedPayloadHex(const std::string &encryptedPayloadHex) const;

    /** Aborts the enclave-side reencryption session, logging instead of throwing. */
    void abortDBReencryptNoThrow() const;

    /** Replaces the plaintext backup SEK file with the new temporary one. */
    void replaceBackupSEKFile(const std::string &backupKeyBackupPath) const;
};

#endif // SGXD_DBREENCRYPT_H
