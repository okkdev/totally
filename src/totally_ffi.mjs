export function extract_otp_bits(hmac) {
  const offset = hmac.buffer[hmac.buffer.length - 1] & 15
  const part = hmac.buffer.slice(offset, offset + 4)
  const bits =
    ((part[0] & 127) << 24) | (part[1] << 16) | (part[2] << 8) | part[3]
  return bits
}
