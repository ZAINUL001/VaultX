#pragma once

#include <stdexcept>
#include <string>

namespace vaultx {

/// Base class for all VaultX-specific errors.
class VaultError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

/// The input is not a valid VaultX file (bad magic, truncated, inconsistent header).
class FormatError : public VaultError {
public:
    using VaultError::VaultError;
};

/// Authentication failed: wrong password OR the file was modified.
class AuthError : public VaultError {
public:
    using VaultError::VaultError;
};

}  // namespace vaultx
