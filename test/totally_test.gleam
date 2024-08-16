import gleeunit
import gleeunit/should

import totally

pub fn main() {
  gleeunit.main()
}

pub fn totp_test() {
  let secret = <<
    74, 171, 86, 253, 130, 92, 56, 228, 150, 109, 22, 104, 96, 18, 64, 144, 134,
    4, 161, 26,
  >>

  let time = 1_723_813_617
  let period = 30

  totally.totp_from_time_and_period(secret, time, period)
  |> totally.otp_to_string
  |> should.equal("223150")
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

  totally.totp(secret)
  |> totally.otp_to_string
  |> totally.valid(secret)
  |> should.be_true

  "123"
  |> totally.valid(secret)
  |> should.be_false
}
