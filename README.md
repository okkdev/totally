# totally

[![Package Version](https://img.shields.io/hexpm/v/totally)](https://hex.pm/packages/totally)
[![Hex Docs](https://img.shields.io/badge/hex-docs-ffaff3)](https://hexdocs.pm/totally/)

totally (TOTP+ally) is a TOTP (Time-based One-Time Password) library for Gleam (Erlang & Javascript targets).

Implements the [TOTP RFC6238](https://datatracker.ietf.org/doc/html/rfc6238)

Inspired by [NimbleTOTP](https://github.com/dashbitco/nimble_totp) and [OTPAuth](https://github.com/hectorm/otpauth)

## Installation

```sh
gleam add totally
```

## Basic Usage

```gleam
import totally

pub fn main() {
  // Create user secret. This should be stored securely.
  let secret = totally.secret()

  // Generate an OTP auth URI. Display this as a QR code to the user.
  totally.otpauth_uri(secret, issuer: "totally", account: "joe")
  // => "otpauth://totp/totally:joe?secret=JKVVN7MCLQ4OJFTNCZUGAESASCDAJII2&issuer=totally&algorithm=SHA1&digits=6&period=30"

  // Generate a TOTP if you need to send it to the user via another channel
  totally.totp(secret)
  // => OTP("492755")

  let user_input = "492755"

  // Verify a TOTP
  totally.verify(secret, user_input)
  // => true
}
```

## Advanced Usage

```gleam
import totally

pub fn main() {
  let secret = totally.secret()

  // Using the builder pattern
  let config =
    totally.default_config()
    |> totally.set_secret(secret)
    |> totally.set_time_now
    |> totally.set_issuer("totally")
    |> totally.set_account("joe")

  // or the TOTPConfig type directly
  let config =
    TOTPConfig(
      secret: secret,
      time: 1_723_813_617,
      algorithm: totally.SHA1,
      digits: 6,
      period: 30,
      issuer: "totally",
      account: "joe",
    )

  totally.otpauth_uri_from_config(config)

  totally.totp_from_config(config)

  let user_input = "492755"

  totally.verify_from_config(config, user_input)
}
```

Further documentation can be found at <https://hexdocs.pm/totally>.

## Development

```sh
gleam test  # Run the tests
```
