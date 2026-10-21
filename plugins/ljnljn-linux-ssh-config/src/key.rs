//! SSH wire-format helpers: public-key type recognition and bit length.

/// Key types accepted in `authorized_keys` and `*.pub` files.
pub fn is_type(token: &str) -> bool {
    matches!(
        token,
        "ssh-rsa"
            | "ssh-dss"
            | "ssh-ed25519"
            | "sk-ssh-ed25519@openssh.com"
            | "sk-ecdsa-sha2-nistp256@openssh.com"
    ) || token.starts_with("ecdsa-sha2-")
}

/// Bit length of the public key inside the SSH wire blob.
pub fn bits(blob: &[u8]) -> Option<i64> {
    let mut reader = Reader { data: blob, at: 0 };
    let key_type = std::str::from_utf8(reader.string()?).ok()?;
    match key_type {
        "ssh-ed25519" | "sk-ssh-ed25519@openssh.com" => {
            let public = reader.string()?;
            (public.len() == 32).then_some(256)
        }
        "ssh-rsa" => {
            let _exponent = reader.string()?;
            let modulus = reader.string()?;
            Some(mpint_bits(modulus))
        }
        "ssh-dss" => {
            let prime = reader.string()?;
            Some(mpint_bits(prime))
        }
        "ecdsa-sha2-nistp256" | "sk-ecdsa-sha2-nistp256@openssh.com" => {
            let _curve = reader.string()?;
            Some(256)
        }
        "ecdsa-sha2-nistp384" => {
            let _curve = reader.string()?;
            Some(384)
        }
        "ecdsa-sha2-nistp521" => {
            let _curve = reader.string()?;
            Some(521)
        }
        _ => None,
    }
}

fn mpint_bits(bytes: &[u8]) -> i64 {
    let mut start = 0;
    while start < bytes.len() && bytes[start] == 0 {
        start += 1;
    }
    if start == bytes.len() {
        return 0;
    }
    let first = bytes[start];
    ((bytes.len() - start - 1) * 8 + (8 - first.leading_zeros() as usize)) as i64
}

struct Reader<'a> {
    data: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn string(&mut self) -> Option<&'a [u8]> {
        let length = u32::from_be_bytes(self.data.get(self.at..self.at + 4)?.try_into().ok()?) as usize;
        self.at += 4;
        let end = self.at.checked_add(length)?;
        let value = self.data.get(self.at..end)?;
        self.at = end;
        Some(value)
    }
}
