# totally

[![Package Version](https://img.shields.io/hexpm/v/totally)](https://hex.pm/packages/totally)
[![Hex Docs](https://img.shields.io/badge/hex-docs-ffaff3)](https://hexdocs.pm/totally/)

totally (TOTP+ally) is a TOTP (Time-based One-Time Password) library for Gleam (Erlang & Javascript(Node) targets).

Implements the [TOTP RFC6238](https://datatracker.ietf.org/doc/html/rfc6238)

Inspired by [NimbleTOTP](https://github.com/dashbitco/nimble_totp) and [OTPAuth](https://github.com/hectorm/otpauth)

## Installation

```sh
gleam add totally@2
```

## Basic Usage

```gleam
import totally

pub fn main() {
  // Create user secret. This should be stored securely.
  let secret = totally.secret()

  // Generate an OTP auth URI. Display this as a QR code to the user.
  let assert Ok(uri) =
    totally.otpauth_uri(secret: secret, issuer: "totally", account: "joe")
  // => "otpauth://totp/totally:joe?secret=...&issuer=totally&algorithm=SHA1&digits=6&period=30"

  // Generate a TOTP if you need to send it to the user via another channel
  let assert Ok(otp) = totally.totp(secret)
  let code = totally.otp_to_string(otp)

  // Check if a user-provided code is valid
  let assert Ok(True) = totally.is_valid(secret: secret, input: user_input)
}
```

## Advanced Usage

```gleam
import totally

pub fn main() {
  let secret = totally.secret()

  // Build a custom configuration
  let assert Ok(config) = totally.new(secret)
  let config =
    config
    |> totally.set_time_now
    |> totally.set_algorithm(totally.Sha256)
    |> totally.set_digits(totally.Eight)
    |> totally.set_issuer("totally")
    |> totally.set_account("joe")

  // Generate OTP and URI from config
  let otp = totally.totp_from_config(config)
  let uri = totally.otpauth_uri_from_config(config)

  // Verify with replay protection using last use
  assert totally.is_valid_from_config(
    totally.set_last_use(config, last_use_timestamp),
    input: user_input,
  )
}
```

Further documentation can be found at <https://hexdocs.pm/totally>.

## Development

```sh
gleam test  # Run the tests
```
