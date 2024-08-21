export function extract_otp_bits(hmac) {
  const offset = hmac.buffer[hmac.buffer.length - 1] & 15
  const part = hmac.buffer.slice(offset, offset + 4)
  const bits =
    ((part[0] & 127) << 24) |
    ((part[1] & 255) << 16) |
    ((part[2] & 255) << 8) |
    (part[3] & 255)
  return bits
}

export function encode32(input) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
  const intArray = input.buffer
  let output = ""
  let bitBuffer = 0
  let bitCount = 0

  for (let i = 0; i < intArray.length; i++) {
    bitBuffer = (bitBuffer << 8) | intArray[i]
    bitCount += 8

    while (bitCount >= 5) {
      const index = (bitBuffer >> (bitCount - 5)) & 31
      output += alphabet[index]
      bitCount -= 5
    }
  }

  if (bitCount > 0) {
    output += alphabet[(bitBuffer << (5 - bitCount)) & 31]
  }

  return output
}
