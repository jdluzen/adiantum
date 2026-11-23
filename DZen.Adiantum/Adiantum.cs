using DZen.Adiantum.Internal;
using System;
using System.Buffers.Binary;
using System.Security.Cryptography;

namespace DZen.Adiantum;

/// <summary>
/// Adiantum is a length-preserving, tweakable, confidentiality-only cipher.
/// It provides no authentication or integrity protection.
/// </summary>
public sealed class Adiantum : IDisposable
{
    /// <summary>The required key length in bytes.</summary>
    public const int KeySize = 32;
    /// <summary>The minimum supported message length in bytes.</summary>
    public const int MinimumMessageSize = 16;

    private readonly object _gate = new();
    private readonly byte[] _streamKey = new byte[32];
    private readonly byte[] _aesKey = new byte[32];
    private readonly byte[] _headerPolyKey = new byte[16];
    private readonly byte[] _messagePolyKey = new byte[16];
    private readonly byte[] _nhKey = new byte[Nh.KeyBytes];
    private Aes? _aes;
    private bool _disposed;

    /// <summary>Creates an Adiantum cipher from a 32-byte key.</summary>
    public Adiantum(ReadOnlySpan<byte> key)
    {
        if (key.Length != KeySize) throw new ArgumentException("Adiantum keys must be 32 bytes.", nameof(key));

        Span<byte> derived = stackalloc byte[32 + 16 + 16 + Nh.KeyBytes];
        derived.Clear();
        try
        {
            key.CopyTo(_streamKey);
            Span<byte> nonce = stackalloc byte[24];
            nonce.Clear();
            nonce[0] = 1;
            XChaCha12.Crypt(_streamKey, nonce, derived);

            derived[..32].CopyTo(_aesKey);
            derived.Slice(32, 16).CopyTo(_headerPolyKey);
            derived.Slice(48, 16).CopyTo(_messagePolyKey);
            derived[64..].CopyTo(_nhKey);

            _aes = Aes.Create();
            _aes.Mode = CipherMode.ECB;
            _aes.Padding = PaddingMode.None;
            _aes.KeySize = 256;
            _aes.Key = _aesKey;
        }
        catch
        {
            ClearKeys();
            _aes?.Dispose();
            throw;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(derived);
        }
    }

    /// <summary>Encrypts data in place using the supplied tweak.</summary>
    /// <remarks>If processing throws, the data buffer is left unchanged.</remarks>
    public void Encrypt(Span<byte> data, ReadOnlySpan<byte> tweak)
    {
        Crypt(data, tweak, encrypt: true);
    }

    /// <summary>Decrypts data in place using the supplied tweak.</summary>
    /// <remarks>If processing throws, the data buffer is left unchanged.</remarks>
    public void Decrypt(Span<byte> data, ReadOnlySpan<byte> tweak)
    {
        Crypt(data, tweak, encrypt: false);
    }

    private void Crypt(Span<byte> data, ReadOnlySpan<byte> tweak, bool encrypt)
    {
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            if (data.Length < MinimumMessageSize) throw new ArgumentException("Adiantum messages must be at least 16 bytes.", nameof(data));

            Span<byte> scratch = stackalloc byte[104];
            byte[] staging = GC.AllocateUninitializedArray<byte>(data.Length);
            try
            {
                data.CopyTo(staging);
                Span<byte> work = staging;
                Span<byte> pl = work[..^16];
                Span<byte> pr = work[^16..];
                Span<byte> headerHash = scratch[..16];
                HashHeader(tweak, pl.Length, headerHash);
                Span<byte> messageHash = scratch.Slice(16, 16);
                HashMessage(pl, messageHash);

                Span<byte> pm = scratch.Slice(32, 16);
                pr.CopyTo(pm);
                BlockAdd(pm, headerHash);
                BlockAdd(pm, messageHash);

                Span<byte> cm = scratch.Slice(48, 16);
                if (encrypt)
                {
                    _aes!.EncryptEcb(pm, cm, PaddingMode.None);
                }
                else
                {
                    pm.CopyTo(cm);
                    _aes!.DecryptEcb(cm, pm, PaddingMode.None);
                }

                Span<byte> streamNonce = scratch.Slice(64, 24);
                cm.CopyTo(streamNonce);
                streamNonce[16] = 1;
                streamNonce[17..24].Clear();

                XChaCha12.Crypt(_streamKey, streamNonce, pl);
                Span<byte> secondMessageHash = scratch.Slice(88, 16);
                HashMessage(pl, secondMessageHash);
                if (!encrypt)
                {
                    BlockSub(pm, headerHash);
                    BlockSub(pm, secondMessageHash);
                    pm.CopyTo(pr);
                }
                else
                {
                    BlockSub(cm, headerHash);
                    BlockSub(cm, secondMessageHash);
                    cm.CopyTo(pr);
                }

                work.CopyTo(data);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(staging);
                CryptographicOperations.ZeroMemory(scratch);
            }
        }
    }

    private void HashHeader(ReadOnlySpan<byte> tweak, int bulkLength, Span<byte> output)
    {
        Span<byte> header = stackalloc byte[16];
        header.Clear();
        BinaryPrimitives.WriteUInt64LittleEndian(header, checked((ulong)bulkLength * 8));

        using Poly1305.StreamingState poly = new(_headerPolyKey);
        poly.Update(header);
        poly.Update(tweak);
        poly.Finish(output);
    }

    private void HashMessage(ReadOnlySpan<byte> message, Span<byte> output)
    {
        Span<byte> nhHash = stackalloc byte[Nh.HashBytes];
        Span<byte> padded = stackalloc byte[Nh.MessageBytes];
        try
        {
            using Poly1305.StreamingState poly = new(_messagePolyKey);
            int offset = 0;
            while (offset < message.Length)
            {
                int chunkLength = Math.Min(Nh.MessageBytes, message.Length - offset);
                ReadOnlySpan<byte> chunk = message.Slice(offset, chunkLength);
                padded.Clear();
                chunk.CopyTo(padded);
                int nhLength = chunkLength;
                if (nhLength < Nh.MessageUnit || (nhLength & (Nh.MessageUnit - 1)) != 0)
                    nhLength = (nhLength + Nh.MessageUnit - 1) & ~(Nh.MessageUnit - 1);

                Nh.Hash(_nhKey, padded[..nhLength], nhHash);
                poly.Update(nhHash);
                offset += chunkLength;
            }

            poly.Finish(output);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(nhHash);
            CryptographicOperations.ZeroMemory(padded);
        }
    }

    private static void BlockAdd(Span<byte> left, ReadOnlySpan<byte> right)
    {
        ulong a = BinaryPrimitives.ReadUInt64LittleEndian(left);
        ulong b = BinaryPrimitives.ReadUInt64LittleEndian(left[8..]);
        ulong c = BinaryPrimitives.ReadUInt64LittleEndian(right);
        ulong d = BinaryPrimitives.ReadUInt64LittleEndian(right[8..]);
        ulong sumLow = unchecked(a + c);
        ulong carry = sumLow < a ? 1UL : 0UL;
        ulong sumHigh = unchecked(b + d + carry);
        BinaryPrimitives.WriteUInt64LittleEndian(left, sumLow);
        BinaryPrimitives.WriteUInt64LittleEndian(left[8..], sumHigh);
    }

    private static void BlockSub(Span<byte> left, ReadOnlySpan<byte> right)
    {
        ulong a = BinaryPrimitives.ReadUInt64LittleEndian(left);
        ulong b = BinaryPrimitives.ReadUInt64LittleEndian(left[8..]);
        ulong c = BinaryPrimitives.ReadUInt64LittleEndian(right);
        ulong d = BinaryPrimitives.ReadUInt64LittleEndian(right[8..]);
        ulong diffLow = unchecked(a - c);
        ulong borrow = diffLow > a ? 1UL : 0UL;
        ulong diffHigh = unchecked(b - d - borrow);
        BinaryPrimitives.WriteUInt64LittleEndian(left, diffLow);
        BinaryPrimitives.WriteUInt64LittleEndian(left[8..], diffHigh);
    }

    /// <summary>Clears derived key material and disposes the AES transform.</summary>
    public void Dispose()
    {
        lock (_gate)
        {
            if (_disposed) return;
            _disposed = true;
            ClearKeys();
            _aes?.Dispose();
            _aes = null;
        }
    }

    private void ClearKeys()
    {
        CryptographicOperations.ZeroMemory(_streamKey);
        CryptographicOperations.ZeroMemory(_aesKey);
        CryptographicOperations.ZeroMemory(_headerPolyKey);
        CryptographicOperations.ZeroMemory(_messagePolyKey);
        CryptographicOperations.ZeroMemory(_nhKey);
    }
}
