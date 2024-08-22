import birl
import gleam/bit_array
import gleam/crypto
import gleam/float
import gleam/int
import gleam/regex
import gleam/result
import gleam/string
import gleam/uri

type Secret =
  BitArray

/// One Time Password type
pub opaque type OTP {
  OTP(String)
}

/// Algorithm used for the hash function
pub type TOTPAlgorithm {
  Sha1
  Sha256
  Sha512
}

/// Configuration for the TOTP
pub type TOTPConfig {
  TOTPConfig(
    secret: Secret,
    time: Int,
    period: Int,
    digits: Int,
    algorithm: TOTPAlgorithm,
    issuer: String,
    account: String,
  )
}

/// Creates a default configuration for TOTP with the following values:
/// algorithm: Sha1, period: 30, digits: 6. These are the most commonly used TOTP settings.
/// Please set the secret and time with the `set_secret` and `set_time_now` or manually `set_time` functions.
pub fn default_config() -> TOTPConfig {
  TOTPConfig(
    secret: bit_array.from_string(""),
    time: 0,
    period: 30,
    digits: 6,
    algorithm: Sha1,
    issuer: "",
    account: "",
  )
}

/// Sets the secret for the TOTP configuration.
pub fn set_secret(config: TOTPConfig, secret: Secret) -> TOTPConfig {
  TOTPConfig(..config, secret: secret)
}

/// Sets the issuer for the TOTP configuration.
/// Used for the otpauth URI.
pub fn set_issuer(config: TOTPConfig, issuer: String) -> TOTPConfig {
  TOTPConfig(..config, issuer: issuer)
}

/// Sets the account for the TOTP configuration.
pub fn set_account(config: TOTPConfig, account: String) -> TOTPConfig {
  TOTPConfig(..config, account: account)
}

/// Sets the time in unix timestamp seconds for the TOTP configuration.
pub fn set_time(config: TOTPConfig, time: Int) -> TOTPConfig {
  TOTPConfig(..config, time: time)
}

/// Sets the time for the TOTP configuration to the current time.
pub fn set_time_now(config: TOTPConfig) -> TOTPConfig {
  TOTPConfig(..config, time: birl.utc_now() |> birl.to_unix)
}

/// Sets the refresh period in seconds for the TOTP configuration.
/// Most commonly used is 30 seconds.
pub fn set_period(config: TOTPConfig, period: Int) -> TOTPConfig {
  TOTPConfig(..config, period: period)
}

/// Sets the digits for the TOTP configuration.
/// Most commonly used is 6 digits.
/// The spec allows for 6 to 8 digits.
pub fn set_digits(config: TOTPConfig, digits: Int) -> TOTPConfig {
  TOTPConfig(..config, digits: digits)
}

/// Sets the algorithm for the TOTP configuration.
/// Most commonly used is Sha1.
pub fn set_algorithm(config: TOTPConfig, algorithm: TOTPAlgorithm) -> TOTPConfig {
  TOTPConfig(..config, algorithm: algorithm)
}

/// Generates a random 20 byte secret.
/// 20 bytes is the recommended size according to the HOTP RFC4226 (https://tools.ietf.org/html/rfc4226#section-4).
pub fn secret() -> Secret {
  crypto.strong_random_bytes(20)
}

/// Generates a random secret with the given size.
pub fn secret_with_size(size: Int) {
  crypto.strong_random_bytes(size)
}

/// Generates a TOTP using the given secret and default configuration.
pub fn totp(secret: Secret) -> OTP {
  default_config()
  |> set_secret(secret)
  |> set_time_now
  |> totp_from_config
}

/// Generates a TOTP using the given TOTP configuration.
pub fn totp_from_config(config: TOTPConfig) -> OTP {
  let payload =
    int.floor_divide(config.time, config.period)
    // Please don't use 0 period...
    |> result.unwrap(0)

  let rem_digits =
    int.power(10, int.to_float(config.digits))
    |> result.unwrap(0.0)
    |> float.truncate

  let algo = case config.algorithm {
    Sha1 -> crypto.Sha1
    Sha256 -> crypto.Sha256
    Sha512 -> crypto.Sha512
  }

  crypto.hmac(<<payload:int-size(64)>>, algo, config.secret)
  |> extract_otp_bits
  |> int.remainder(rem_digits)
  |> result.unwrap(0)
  |> int.to_string
  |> string.pad_left(config.digits, "0")
  |> OTP
}

/// Verifies the given TOTP input with the given secret.
pub fn verify(secret secret: Secret, input totp_input: String) -> Bool {
  totp(secret) == OTP(totp_input)
}

/// Verifies the given TOTP input with the given TOTP configuration.
pub fn verify_from_config(config: TOTPConfig, input totp_input: String) -> Bool {
  totp(config.secret) == OTP(totp_input)
}

/// Converts the OTP to a string.
pub fn otp_to_string(otp: OTP) -> String {
  let OTP(otp) = otp
  otp
}

/// Converts a valid OTP string to an OTP type.
pub fn string_to_otp(otp: String) -> Result(OTP, String) {
  case string.length(otp) {
    6 | 7 | 8 ->
      case valid_otp_code(otp) {
        True -> Ok(OTP(otp))
        False -> Error("Invalid OTP")
      }
    _ -> Error("Invalid OTP length")
  }
}

/// Generates an otpauth URI for the given secret, issuer and account name.
/// The otpauth URI is used to generate QR codes for TOTP.
pub fn otpauth_uri(
  secret secret: Secret,
  issuer issuer: String,
  account account_name: String,
) -> String {
  default_config()
  |> set_secret(secret)
  |> set_issuer(issuer)
  |> set_account(account_name)
  |> otpauth_uri_from_config
}

/// Generates an otpauth URI for the given TOTP configuration.
pub fn otpauth_uri_from_config(config: TOTPConfig) -> String {
  let issuer = uri.percent_encode(config.issuer)

  let algo = case config.algorithm {
    Sha1 -> "SHA1"
    Sha256 -> "SHA256"
    Sha512 -> "SHA512"
  }

  string.join(
    [
      "otpauth://totp/",
      issuer,
      ":",
      uri.percent_encode(config.account),
      "?secret=",
      encode32(config.secret),
      "&issuer=",
      issuer,
      "&algorithm=",
      algo,
      "&digits=",
      int.to_string(config.digits),
      "&period=",
      int.to_string(config.period),
    ],
    "",
  )
}

/// Checks if the string fits the otp format.
fn valid_otp_code(otp: String) -> Bool {
  let assert Ok(re) = regex.from_string("^[0-9]{6,8}$")
  regex.check(re, otp)
}

/// Encodes the given BitArray to a base32 string.
@external(erlang, "totally_ffi", "encode32")
@external(javascript, "./totally_ffi.mjs", "encode32")
fn encode32(input: BitArray) -> String

/// Extracts the OTP bits from the HMAC hash.
@external(javascript, "./totally_ffi.mjs", "extract_otp_bits")
fn extract_otp_bits(hmac: BitArray) -> Int {
  let off_offset = bit_array.byte_size(hmac) * 8 - 4
  let assert <<_:size(off_offset), offset:int-size(4)>> = hmac
  let assert <<_:bytes-size(offset), part:bytes-size(4), _:bytes>> = hmac
  let assert <<_:size(1), bits:int-size(31)>> = part
  bits
}
