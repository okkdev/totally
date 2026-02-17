import gleam/time/timestamp
import gleeunit

import totally.{Eight, Sha256, Sha512}

pub fn main() {
  gleeunit.main()
}

const secret = <<
  74, 171, 86, 253, 130, 92, 56, 228, 150, 109, 22, 104, 96, 18, 64, 144, 134, 4,
  161, 26,
>>

const time = 1_723_813_617

pub fn totp_sha1_test() {
  let assert Ok(config) = totally.new(secret)

  let otp =
    config
    |> totally.set_time(timestamp.from_unix_seconds(time))
    |> totally.totp_from_config

  assert totally.otp_to_string(otp) == "223150"
}

pub fn totp_sha1_8digits_test() {
  let assert Ok(config) = totally.new(secret)

  let otp =
    config
    |> totally.set_time(timestamp.from_unix_seconds(time))
    |> totally.set_digits(Eight)
    |> totally.totp_from_config

  assert totally.otp_to_string(otp) == "16223150"
}

pub fn totp_sha256_test() {
  let assert Ok(config) = totally.new(secret)

  let otp =
    config
    |> totally.set_time(timestamp.from_unix_seconds(time))
    |> totally.set_algorithm(Sha256)
    |> totally.totp_from_config

  assert totally.otp_to_string(otp) == "944204"
}

pub fn totp_sha256_8digits_test() {
  let assert Ok(config) = totally.new(secret)

  let otp =
    config
    |> totally.set_time(timestamp.from_unix_seconds(time))
    |> totally.set_algorithm(Sha256)
    |> totally.set_digits(Eight)
    |> totally.totp_from_config

  assert totally.otp_to_string(otp) == "31944204"
}

pub fn totp_sha512_test() {
  let assert Ok(config) = totally.new(secret)

  let otp =
    config
    |> totally.set_time(timestamp.from_unix_seconds(time))
    |> totally.set_algorithm(Sha512)
    |> totally.totp_from_config

  assert totally.otp_to_string(otp) == "635524"
}

pub fn totp_sha512_8digits_test() {
  let assert Ok(config) = totally.new(secret)

  let otp =
    config
    |> totally.set_time(timestamp.from_unix_seconds(time))
    |> totally.set_algorithm(Sha512)
    |> totally.set_digits(Eight)
    |> totally.totp_from_config

  assert totally.otp_to_string(otp) == "31635524"
}

pub fn string_test() {
  let assert Error(totally.InvalidOtpLength) = totally.string_to_otp("123")
  let assert Error(totally.InvalidOtp) = totally.string_to_otp("123abc")
  let assert Ok(_) = totally.string_to_otp("123456")
}

pub fn valid_test() {
  let secret = totally.secret()

  let assert Ok(otp) = totally.totp(secret)
  let input = totally.otp_to_string(otp)

  let assert Ok(True) = totally.is_valid(secret: secret, input: input)

  let assert Ok(False) = totally.is_valid(secret: secret, input: "123")
}

pub fn otpauth_uri_test() {
  let assert Ok(uri) =
    totally.otpauth_uri(secret: secret, issuer: "issuer", account: "account")

  assert uri
    == "otpauth://totp/issuer:account?secret=JKVVN7MCLQ4OJFTNCZUGAESASCDAJII2&issuer=issuer&algorithm=SHA1&digits=6&period=30"
}

pub fn reuse_test() {
  let assert Ok(config) = totally.new(secret)

  // Generate OTP for "now"
  let config = totally.set_time_now(config)
  let input =
    totally.totp_from_config(config)
    |> totally.otp_to_string

  // last_use is in the current timestep — should be rejected as reused
  let reused_config = totally.set_last_use_now(config)
  assert !totally.is_valid_from_config(reused_config, input)

  // last_use is far in the past — should be accepted
  let fresh_config =
    totally.set_last_use(config, timestamp.from_unix_seconds(0))
  assert totally.is_valid_from_config(fresh_config, input)
}
