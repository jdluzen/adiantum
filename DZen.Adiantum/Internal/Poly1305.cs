using System;
using System.Buffers.Binary;
using System.Numerics;

namespace DZen.Adiantum.Internal;

internal static class Poly1305
{
    private static readonly BigInteger Modulus = (BigInteger.One << 130) - 5;
    private static readonly BigInteger Clamp =
        BigInteger.Parse("0ffffffc0ffffffc0ffffffc0fffffff", System.Globalization.NumberStyles.HexNumber);

    internal static void Process(ReadOnlySpan<byte> key, ReadOnlySpan<byte> message, Span<byte> output)
    {
        if (key.Length != 16) throw new ArgumentException("A Poly1305 key must be 16 bytes.", nameof(key));
        if (output.Length != 16) throw new ArgumentException("A Poly1305 output must be 16 bytes.", nameof(output));

        BigInteger r = new BigInteger(key.ToArray(), isUnsigned: true, isBigEndian: false);
        r &= (BigInteger.One << 128) - 1;
        r &= Clamp;

        BigInteger h = 0;
        int offset = 0;
        while (offset < message.Length)
        {
            int blockLength = Math.Min(16, message.Length - offset);
            byte[] block = message.Slice(offset, blockLength).ToArray();
            BigInteger c = new BigInteger(block, isUnsigned: true, isBigEndian: false);
            c += BigInteger.One << (8 * blockLength);
            h = ((h + c) * r) % Modulus;
            offset += blockLength;
        }

        output.Clear();
        h.ToByteArray(isUnsigned: true, isBigEndian: false).AsSpan(0, Math.Min(h.ToByteArray().Length, 16)).CopyTo(output);
    }

    internal static void HashWithoutFinalization(ReadOnlySpan<byte> key, ReadOnlySpan<byte> message, Span<byte> output)
    {
        if (key.Length != 16) throw new ArgumentException("A Poly1305 key must be 16 bytes.", nameof(key));
        if (output.Length != 16) throw new ArgumentException("A Poly1305 output must be 16 bytes.", nameof(output));

        BigInteger r = new BigInteger(key.ToArray(), isUnsigned: true, isBigEndian: false);
        r &= (BigInteger.One << 128) - 1;
        r &= Clamp;
        BigInteger h = 0;

        int offset = 0;
        while (offset < message.Length)
        {
            int blockLength = Math.Min(16, message.Length - offset);
            byte[] block = message.Slice(offset, blockLength).ToArray();
            BigInteger c = new BigInteger(block, isUnsigned: true, isBigEndian: false);
            c += BigInteger.One << (8 * blockLength);
            h = ((h + c) * r) % Modulus;
            offset += blockLength;
        }

        Span<byte> temp = stackalloc byte[16];
        h.ToByteArray(isUnsigned: true, isBigEndian: false).AsSpan(0, Math.Min(h.ToByteArray().Length, 16)).CopyTo(temp);
        temp.CopyTo(output);
    }
}
