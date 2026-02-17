import gleam/bit_array
import gleam/bool
import gleam/crypto
import gleam/float
import gleam/int
import gleam/list
import gleam/result
import gleam/string
import gleam/time/timestamp
import gleam/uri

type Secret =
  BitArray

/// One Time Password type
pub opaque type Otp {
  Otp(String)
}

/// Algorithm used for the hash function
pub type TotpAlgorithm {
  Sha1
  Sha256
  Sha512
}

/// Number of digits in the OTP.
/// The spec allows for 6 to 8 digits.
pub type Digits {
  Six
  Seven
  Eight
}

/// Configuration for the TOTP.
/// Create one with `new` and customize it with the `set_*` functions.
pub opaque type TotpConfig {
  TotpConfig(
    secret: Secret,
    time: timestamp.Timestamp,
    period: Int,
    last_use: timestamp.Timestamp,
    digits: Digits,
    algorithm: TotpAlgorithm,
    issuer: String,
    account: String,
  )
}

pub type TotpError {
  InsecureSecret
  InvalidPeriod
  InvalidOtp
  InvalidOtpLength
}

/// Creates a TOTP configuration with the given secret and default values:
/// algorithm: Sha1, period: 30, digits: 6. These are the most commonly used TOTP settings.
/// The secret must be at least 16 bytes (128 bits).
pub fn new(secret: Secret) -> Result(TotpConfig, TotpError) {
  use <- bool.guard(
    when: bit_array.byte_size(secret) < 16,
    return: Error(InsecureSecret),
  )
  Ok(TotpConfig(
    secret: secret,
    time: timestamp.from_unix_seconds(0),
    period: 30,
    last_use: timestamp.from_unix_seconds(0),
    digits: Six,
    algorithm: Sha1,
    issuer: "",
    account: "",
  ))
}

/// Sets the issuer for the TOTP configuration.
/// Used for the otpauth URI.
pub fn set_issuer(config: TotpConfig, issuer: String) -> TotpConfig {
  TotpConfig(..config, issuer: issuer)
}

/// Sets the account for the TOTP configuration.
pub fn set_account(config: TotpConfig, account: String) -> TotpConfig {
  TotpConfig(..config, account: account)
}

/// Sets the time for OTP generation.
/// This is only used by `totp_from_config`. Verification functions
/// use the current time automatically.
pub fn set_time(config: TotpConfig, time: timestamp.Timestamp) -> TotpConfig {
  TotpConfig(..config, time: time)
}

/// Sets the time for OTP generation to the current time.
/// This is only used by `totp_from_config`. Verification functions
/// use the current time automatically.
pub fn set_time_now(config: TotpConfig) -> TotpConfig {
  TotpConfig(..config, time: timestamp.system_time())
}

/// Sets the refresh period in seconds for the TOTP configuration.
/// Must be greater than 0.
pub fn set_period(
  config: TotpConfig,
  period: Int,
) -> Result(TotpConfig, TotpError) {
  use <- bool.guard(when: period <= 0, return: Error(InvalidPeriod))
  Ok(TotpConfig(..config, period: period))
}

/// Sets the last use time for the TOTP configuration.
/// Used to prevent replay attacks.
pub fn set_last_use(
  config: TotpConfig,
  last_use: timestamp.Timestamp,
) -> TotpConfig {
  TotpConfig(..config, last_use: last_use)
}

/// Sets the last use time for the TOTP configuration to the current time.
pub fn set_last_use_now(config: TotpConfig) -> TotpConfig {
  TotpConfig(..config, last_use: timestamp.system_time())
}

/// Sets the digits for the TOTP configuration.
pub fn set_digits(config: TotpConfig, digits: Digits) -> TotpConfig {
  TotpConfig(..config, digits: digits)
}

/// Sets the algorithm for the TOTP configuration.
/// Most commonly used is Sha1.
pub fn set_algorithm(config: TotpConfig, algorithm: TotpAlgorithm) -> TotpConfig {
  TotpConfig(..config, algorithm: algorithm)
}

/// Generates a random 20 byte secret.
/// 20 bytes is the recommended size according to the HOTP RFC4226 (https://tools.ietf.org/html/rfc4226#section-4).
pub fn secret() -> Secret {
  crypto.strong_random_bytes(20)
}

/// Generates a random secret with the given size.
/// Must be at least 16 bytes.
pub fn secret_with_size(size: Int) -> Result(Secret, TotpError) {
  case size < 16 {
    False -> Ok(crypto.strong_random_bytes(size))
    True -> Error(InsecureSecret)
  }
}

/// Generates a TOTP using the given secret and default configuration.
/// The secret must be at least 16 bytes (128 bits).
pub fn totp(secret: Secret) -> Result(Otp, TotpError) {
  use config <- result.try(new(secret))
  config
  |> set_time_now
  |> totp_from_config
  |> Ok
}

/// Generates a TOTP using the given TOTP configuration.
/// Make sure to set the time with `set_time` or `set_time_now` first.
pub fn totp_from_config(config: TotpConfig) -> Otp {
  let payload = timestep(config.time, config.period)

  let num_digits = digits_to_int(config.digits)
  let rem_digits = digits_to_modulo(config.digits)

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
  |> string.pad_start(num_digits, "0")
  |> Otp
}

/// Checks if the given TOTP input matches the current code for the secret.
/// Does not check for replay attacks. Use `is_valid_with_last_use` or
/// `is_valid_from_config` with `set_last_use` for replay protection.
pub fn is_valid(
  secret secret: Secret,
  input totp_input: String,
) -> Result(Bool, TotpError) {
  use otp <- result.try(totp(secret))
  Ok(otp == Otp(totp_input))
}

/// Checks if the given TOTP input matches the current code for the secret,
/// rejecting codes that were already used in the same time window as `last_use`.
pub fn is_valid_with_last_use(
  secret secret: Secret,
  input totp_input: String,
  last_use last_use: timestamp.Timestamp,
) -> Result(Bool, TotpError) {
  use config <- result.try(new(secret))
  config
  |> set_time_now
  |> set_last_use(last_use)
  |> is_valid_from_config(totp_input)
  |> Ok
}

/// Verifies the given TOTP input with the given TOTP configuration.
/// Automatically uses the current time for verification.
pub fn is_valid_from_config(
  config: TotpConfig,
  input totp_input: String,
) -> Bool {
  let now = timestamp.system_time()
  let match = { set_time(config, now) |> totp_from_config } == Otp(totp_input)
  let reused =
    timestep(now, config.period) <= timestep(config.last_use, config.period)
  match && !reused
}

/// Converts the OTP to a string.
pub fn otp_to_string(otp: Otp) -> String {
  let Otp(otp) = otp
  otp
}

/// Converts a valid OTP string to an OTP type.
pub fn string_to_otp(otp: String) -> Result(Otp, TotpError) {
  case string.length(otp) {
    6 | 7 | 8 ->
      case all_digits(otp) {
        True -> Ok(Otp(otp))
        False -> Error(InvalidOtp)
      }
    _ -> Error(InvalidOtpLength)
  }
}

/// Generates an otpauth URI for the given secret, issuer and account name.
/// The secret must be at least 16 bytes (128 bits).
/// The otpauth URI is used to generate QR codes for TOTP.
pub fn otpauth_uri(
  secret secret: Secret,
  issuer issuer: String,
  account account_name: String,
) -> Result(String, TotpError) {
  use config <- result.try(new(secret))
  config
  |> set_issuer(issuer)
  |> set_account(account_name)
  |> otpauth_uri_from_config
  |> Ok
}

/// Generates an otpauth URI for the given TOTP configuration.
pub fn otpauth_uri_from_config(config: TotpConfig) -> String {
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
      int.to_string(digits_to_int(config.digits)),
      "&period=",
      int.to_string(config.period),
    ],
    "",
  )
}

fn digits_to_int(digits: Digits) -> Int {
  case digits {
    Six -> 6
    Seven -> 7
    Eight -> 8
  }
}

fn digits_to_modulo(digits: Digits) -> Int {
  case digits {
    Six -> 1_000_000
    Seven -> 10_000_000
    Eight -> 100_000_000
  }
}

fn timestep(time: timestamp.Timestamp, period: Int) -> Int {
  int.floor_divide(timestamp.to_unix_seconds(time) |> float.truncate, period)
  |> result.unwrap(0)
}

/// Checks if the string fits the otp format.
fn all_digits(otp: String) -> Bool {
  string.to_graphemes(otp)
  |> list.all(fn(c) {
    case c {
      "0" | "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" -> True
      _ -> False
    }
  })
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
