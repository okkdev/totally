# totally

[![Package Version](https://img.shields.io/hexpm/v/totally)](https://hex.pm/packages/totally)
[![Hex Docs](https://img.shields.io/badge/hex-docs-ffaff3)](https://hexdocs.pm/totally/)

totally (TOTP+ally) is a TOTP library for Gleam.

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

  let user_input = "492755"

  // Verify a TOTP
  totally.verify(secret, user_input)
  // => true
}
```

Further documentation can be found at <https://hexdocs.pm/totally>.

## Development

```sh
gleam test  # Run the tests
```
