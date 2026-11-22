# DZen.Adiantum

A pure managed C# implementation of **Adiantum**, Google's length-preserving,
tweakable encryption construction for data such as storage sectors. It uses
XChaCha12, AES-256, NH, and Poly1305, with a portable scalar path and
SSE2, AVX2, and AVX-512F acceleration for NH on supported x86/x64 processors.

[![NuGet](https://img.shields.io/nuget/v/DZen.Adiantum)](https://www.nuget.org/packages/DZen.Adiantum)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![.NET 10](https://img.shields.io/badge/.NET-10.0-blue)](https://dotnet.microsoft.com)

---

## What it does

Adiantum is a wide-block encryption construction: it transforms an entire
input as one unit while preserving its length. It combines a tweakable hash
with AES-256 and XChaCha12 in the HBSH construction. The result is suitable for
length-preserving encryption use cases where conventional authenticated
encryption would add bytes.

The implementation provides:

- In-place encryption and decryption over `Span<byte>`.
- A caller-supplied tweak, with no nonce or metadata added to the data.
- Managed NH, Poly1305, and XChaCha12 implementations.
- AES-256 single-block operations through the .NET cryptography API.
- Published known-answer-vector coverage for NH, Poly1305, XChaCha12, and
  Adiantum.

The current SIMD work targets NH on x86/x64. ARM64 AdvSimd/NEON support is
deferred; all platforms retain a scalar NH fallback.

---

## Hardware acceleration

NH uses runtime CPU detection to process multiple 32-bit message words in
parallel. It selects AVX-512F, AVX2, or SSE2 when supported, then falls back
to scalar code. The SIMD implementations use safe .NET intrinsics. Poly1305
and XChaCha12 remain scalar in this release. ARM64 AdvSimd/NEON is deferred.

Run the console-only microbenchmark with:

```shell
dotnet run --project test/Benchmark -c Release
```

It reports scalar and supported x86 NH paths at several input lengths, plus
end-to-end Adiantum timings. It does not write benchmark results to files.

---

## Installation

The NuGet package ID is `DZen.Adiantum`. Once the package is available from
NuGet, install it with:

```shell
dotnet add package DZen.Adiantum
```

The library targets **.NET 10.0**. It has no third-party runtime dependencies.

---

## API

```csharp
namespace DZen.Adiantum;

public sealed class Adiantum : IDisposable
{
    public const int KeySize = 32;
    public const int MinimumMessageSize = 16;

    public Adiantum(ReadOnlySpan<byte> key);
    public void Encrypt(Span<byte> data, ReadOnlySpan<byte> tweak);
    public void Decrypt(Span<byte> data, ReadOnlySpan<byte> tweak);
    public void Dispose();
}
```

The key must be exactly 32 bytes. Data must contain at least 16 bytes.
Encryption and decryption operate in place and preserve the input length.
Tweak bytes are supplied by the caller and are not serialized into the output.

---

## Usage

```csharp
using System.Security.Cryptography;
using DZen.Adiantum;

byte[] key = RandomNumberGenerator.GetBytes(Adiantum.KeySize);
byte[] tweak = GetStableTweakForThisData();
byte[] data = ReadData();

using var cipher = new Adiantum(key);
cipher.Encrypt(data, tweak);

// Store or transmit the ciphertext and retain the tweak separately.
// To recover the original data, use the same key and tweak:
cipher.Decrypt(data, tweak);
```

Keep the key secret and use a consistent, unambiguous tweak scheme for the
encrypted data. A common use is to derive a tweak from a stable data-unit
identifier. Tweak design and uniqueness are the caller's responsibility.

---

## Security considerations

**Adiantum provides confidentiality only.** It does not authenticate data or
detect modification. Do not treat it as an AEAD or rely on it for integrity;
use a separate, appropriate integrity/authentication mechanism when required.

This implementation has not received an independent security audit or formal
verification. In particular, its current Poly1305 scalar implementation uses
`BigInteger` arithmetic, which is not guaranteed to execute in constant time.
Do not assume it is suitable for threat models that require constant-time
secret arithmetic. Published-vector and round-trip tests demonstrate
interoperability and functional behavior, not a security certification.

---

## Building from source

```shell
git clone https://github.com/jdluzen/adiantum
cd adiantum
dotnet build -c Release
```

Run the published scalar known-answer vectors with:

```shell
dotnet run --project test/DZen.Adiantum.Test
```

The existing NH and Poly1305 test projects can be run with:

```shell
dotnet test test/NH.Test
dotnet test test/Poly1305.Test
```

---

## References

- [Adiantum and HPolyC](https://github.com/google/adiantum) — construction,
  paper, and published test vectors.
- [Linux Adiantum implementation](https://github.com/torvalds/linux/blob/master/crypto/adiantum.c)
- [Independent Go implementation](https://github.com/lukechampine/adiantum)
- [Adiantum paper](https://eprint.iacr.org/2018/720.pdf)

---

## License

Project code is licensed under the MIT License; see [LICENSE](LICENSE).
Third-party attribution is listed in [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).
