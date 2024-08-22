import gleeunit
import gleeunit/should

import totally.{Sha1, Sha256, Sha512, TOTPConfig}

pub fn main() {
  gleeunit.main()
}

const secret = <<
  74, 171, 86, 253, 130, 92, 56, 228, 150, 109, 22, 104, 96, 18, 64, 144, 134, 4,
  161, 26,
>>

const time = 1_723_813_617

pub fn totp_sha1_test() {
  let config =
    TOTPConfig(
      secret: secret,
      time: time,
      period: 30,
      digits: 6,
      algorithm: Sha1,
      issuer: "",
      account: "",
    )

  totally.totp_from_config(config)
  |> totally.otp_to_string
  |> should.equal("223150")
}

pub fn totp_sha1_8digits_test() {
  let config =
    TOTPConfig(
      secret: secret,
      time: time,
      period: 30,
      digits: 8,
      algorithm: Sha1,
      issuer: "",
      account: "",
    )

  totally.totp_from_config(config)
  |> totally.otp_to_string
  |> should.equal("16223150")
}

pub fn totp_sha256_test() {
  let config =
    TOTPConfig(
      secret: secret,
      time: time,
      period: 30,
      digits: 6,
      algorithm: Sha256,
      issuer: "",
      account: "",
    )

  totally.totp_from_config(config)
  |> totally.otp_to_string
  |> should.equal("944204")
}

pub fn totp_sha256_8digits_test() {
  let config =
    TOTPConfig(
      secret: secret,
      time: time,
      period: 30,
      digits: 8,
      algorithm: Sha256,
      issuer: "",
      account: "",
    )

  totally.totp_from_config(config)
  |> totally.otp_to_string
  |> should.equal("31944204")
}

pub fn totp_sha512_test() {
  let config =
    TOTPConfig(
      secret: secret,
      time: time,
      period: 30,
      digits: 6,
      algorithm: Sha512,
      issuer: "",
      account: "",
    )

  totally.totp_from_config(config)
  |> totally.otp_to_string
  |> should.equal("635524")
}

pub fn totp_sha512_8digits_test() {
  let config =
    TOTPConfig(
      secret: secret,
      time: time,
      period: 30,
      digits: 8,
      algorithm: Sha512,
      issuer: "",
      account: "",
    )

  totally.totp_from_config(config)
  |> totally.otp_to_string
  |> should.equal("31635524")
}

pub fn string_test() {
  "123"
  |> totally.string_to_otp
  |> should.be_error

  "123abc"
  |> totally.string_to_otp
  |> should.be_error

  "123456"
  |> totally.string_to_otp
  |> should.be_ok
}

pub fn valid_test() {
  let secret = totally.secret()

  let input =
    totally.totp(secret)
    |> totally.otp_to_string

  totally.verify(secret, input)
  |> should.be_true

  totally.verify(secret, "123")
  |> should.be_false
}

pub fn otpauth_uri_test() {
  totally.otpauth_uri(secret, issuer: "issuer", account: "account")
  |> should.equal(
    "otpauth://totp/issuer:account?secret=JKVVN7MCLQ4OJFTNCZUGAESASCDAJII2&issuer=issuer&algorithm=SHA1&digits=6&period=30",
  )
}
