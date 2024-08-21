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

pub opaque type OTP {
  OTP(String)
}

pub type TOTPAlgorithm {
  Sha1
  Sha256
  Sha512
}

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

pub fn set_secret(config: TOTPConfig, secret: Secret) -> TOTPConfig {
  TOTPConfig(..config, secret: secret)
}

pub fn set_issuer(config: TOTPConfig, issuer: String) -> TOTPConfig {
  TOTPConfig(..config, issuer: issuer)
}

pub fn set_account(config: TOTPConfig, account: String) -> TOTPConfig {
  TOTPConfig(..config, account: account)
}

pub fn set_time(config: TOTPConfig, time: Int) -> TOTPConfig {
  TOTPConfig(..config, time: time)
}

pub fn set_time_now(config: TOTPConfig) -> TOTPConfig {
  TOTPConfig(..config, time: birl.utc_now() |> birl.to_unix)
}

pub fn set_period(config: TOTPConfig, period: Int) -> TOTPConfig {
  TOTPConfig(..config, period: period)
}

pub fn set_digits(config: TOTPConfig, digits: Int) -> TOTPConfig {
  TOTPConfig(..config, digits: digits)
}

pub fn set_algorithm(config: TOTPConfig, algorithm: TOTPAlgorithm) -> TOTPConfig {
  TOTPConfig(..config, algorithm: algorithm)
}

pub fn secret() -> Secret {
  crypto.strong_random_bytes(20)
}

pub fn secret_with_size(size: Int) {
  crypto.strong_random_bytes(size)
}

pub fn totp(secret: Secret) -> OTP {
  default_config()
  |> set_secret(secret)
  |> set_time_now
  |> totp_from_config
}

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

pub fn verify(totp_input: String, secret: Secret) -> Bool {
  totp(secret) == OTP(totp_input)
}

pub fn otp_to_string(otp: OTP) -> String {
  let OTP(otp) = otp
  otp
}

pub fn string_to_otp(otp: String) -> Result(OTP, String) {
  case string.length(otp) {
    6 ->
      case valid_otp_code(otp) {
        True -> Ok(OTP(otp))
        False -> Error("Invalid OTP")
      }
    _ -> Error("Invalid OTP length")
  }
}

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

fn valid_otp_code(otp: String) -> Bool {
  let assert Ok(re) = regex.from_string("^[0-9]{6}$")
  regex.check(re, otp)
}

@external(erlang, "totally_ffi", "encode32")
@external(javascript, "./totally_ffi.mjs", "encode32")
fn encode32(input: BitArray) -> String

@external(javascript, "./totally_ffi.mjs", "extract_otp_bits")
fn extract_otp_bits(hmac: BitArray) -> Int {
  let off_offset = bit_array.byte_size(hmac) * 8 - 4
  let assert <<_:size(off_offset), offset:int-size(4)>> = hmac
  let assert <<_:bytes-size(offset), part:bytes-size(4), _:bytes>> = hmac
  let assert <<_:size(1), bits:int-size(31)>> = part
  bits
}
