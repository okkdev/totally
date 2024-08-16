import birl
import gleam/crypto
import gleam/int
import gleam/regex
import gleam/result
import gleam/string

type Secret =
  BitArray

pub opaque type OTP {
  OTP(String)
}

pub fn secret() -> Secret {
  crypto.strong_random_bytes(20)
}

pub fn totp(secret: Secret) -> OTP {
  let time = birl.utc_now() |> birl.to_unix
  totp_from_time_and_period(secret, time, 30)
}

pub fn totp_from_time_and_period(
  secret: Secret,
  unix_time: Int,
  period: Int,
) -> OTP {
  let assert Ok(x) = int.floor_divide(unix_time, period)

  crypto.hmac(<<x:size(64)>>, crypto.Sha1, secret)
  |> extract_otp_bits
  |> int.remainder(1_000_000)
  // This should never fail
  |> result.unwrap(0)
  |> int.to_string
  |> string.pad_left(6, "0")
  |> OTP
}

pub fn valid(totp_input: String, secret: Secret) -> Bool {
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

fn valid_otp_code(otp: String) -> Bool {
  let assert Ok(re) = regex.from_string("^[0-9]{6}$")
  regex.check(re, otp)
}

@external(javascript, "./totally_ffi.mjs", "extract_otp_bits")
fn extract_otp_bits(hmac: BitArray) -> Int {
  let assert <<_:size(156), offset:int-size(4)>> = hmac
  let assert <<_:bytes-size(offset), part:bytes-size(4), _:bytes>> = hmac
  let assert <<_:size(1), bits:int-size(31)>> = part
  bits
}
