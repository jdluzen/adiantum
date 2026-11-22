# DZen.Adiantum

`DZen.Adiantum` is a pure managed C# implementation of Google's Adiantum
tweakable, length-preserving encryption construction. It uses XChaCha12,
AES-256, NH, and Poly1305.

## Usage

```csharp
using DZen.Adiantum;

byte[] key = ...; // exactly 32 bytes
byte[] tweak = ...;

using var cipher = new Adiantum(key);
cipher.Encrypt(data, tweak);
cipher.Decrypt(data, tweak);
```

The data span must be at least 16 bytes. Encryption and decryption operate in
place and preserve length. Tweak length is not silently normalized.

## Security limitations

Adiantum does not provide authentication or integrity. It must not be used as
an AEAD or to detect ciphertext modification. Tweak reuse must be managed by
the caller. This implementation has been validated against published vectors,
but it has not been independently audited or formally verified.
