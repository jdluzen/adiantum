using System;
using System.Buffers.Binary;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;
using System.Security.Cryptography;

namespace DZen.Adiantum.Internal;

internal static class Nh
{
    internal const int PairStride = 2;
    internal const int NumPasses = 4;
    internal const int UnitCount = 64;
    internal const int MessageUnit = PairStride * 2 * sizeof(uint);
    internal const int MessageBytes = MessageUnit * UnitCount;
    internal const int KeyBytes = MessageUnit * (UnitCount + NumPasses - 1);
    internal const int HashBytes = NumPasses * sizeof(ulong);
    private const byte FirstPairShuffle = 0x50;
    private const byte SecondPairShuffle = 0xFA;

    internal static void Hash(ReadOnlySpan<byte> key, ReadOnlySpan<byte> message, Span<byte> output)
    {
        ValidateArguments(key, message, output);

        if (Avx512F.IsSupported && message.Length >= 64)
        {
            HashAvx512Validated(key, message, output);
            return;
        }

        if (Avx2.IsSupported && message.Length >= 32)
        {
            HashAvx2Validated(key, message, output);
            return;
        }

        if (Sse2.IsSupported && message.Length >= 32)
        {
            HashSse2Validated(key, message, output);
            return;
        }

        HashScalarValidated(key, message, output);
    }

    internal static void HashScalar(ReadOnlySpan<byte> key, ReadOnlySpan<byte> message, Span<byte> output)
    {
        ValidateArguments(key, message, output);
        HashScalarValidated(key, message, output);
    }

    internal static void HashSse2(ReadOnlySpan<byte> key, ReadOnlySpan<byte> message, Span<byte> output)
    {
        ValidateArguments(key, message, output);
        if (!Sse2.IsSupported)
            throw new PlatformNotSupportedException("The SSE2 NH implementation is not supported on this processor.");
        HashSse2Validated(key, message, output);
    }

    internal static void HashAvx2(ReadOnlySpan<byte> key, ReadOnlySpan<byte> message, Span<byte> output)
    {
        ValidateArguments(key, message, output);
        if (!Avx2.IsSupported)
            throw new PlatformNotSupportedException("The AVX2 NH implementation is not supported on this processor.");
        HashAvx2Validated(key, message, output);
    }

    internal static void HashAvx512(ReadOnlySpan<byte> key, ReadOnlySpan<byte> message, Span<byte> output)
    {
        ValidateArguments(key, message, output);
        if (!Avx512F.IsSupported)
            throw new PlatformNotSupportedException("The AVX-512F NH implementation is not supported on this processor.");
        HashAvx512Validated(key, message, output);
    }

    private static void ValidateArguments(ReadOnlySpan<byte> key, ReadOnlySpan<byte> message, Span<byte> output)
    {
        if (key.Length != KeyBytes) throw new ArgumentException("Invalid NH key length.", nameof(key));
        if (message.Length == 0 || message.Length > MessageBytes || (message.Length & 15) != 0)
            throw new ArgumentException("NH message must be non-empty and a multiple of 16 bytes.", nameof(message));
        if (output.Length != HashBytes) throw new ArgumentException("Invalid NH output length.", nameof(output));
    }

    private static void HashScalarValidated(ReadOnlySpan<byte> key, ReadOnlySpan<byte> message, Span<byte> output)
    {
        Span<ulong> sums = stackalloc ulong[NumPasses];
        sums.Clear();
        int keyIndex = 0;
        for (int messageIndex = 0; messageIndex < message.Length; messageIndex += MessageUnit)
        {
            uint m0 = BinaryPrimitives.ReadUInt32LittleEndian(message[messageIndex..]);
            uint m1 = BinaryPrimitives.ReadUInt32LittleEndian(message[(messageIndex + 4)..]);
            uint m2 = BinaryPrimitives.ReadUInt32LittleEndian(message[(messageIndex + 8)..]);
            uint m3 = BinaryPrimitives.ReadUInt32LittleEndian(message[(messageIndex + 12)..]);

            sums[0] += (ulong)(m0 + ReadKey(key, keyIndex + 0)) * (m2 + ReadKey(key, keyIndex + 2));
            sums[1] += (ulong)(m0 + ReadKey(key, keyIndex + 4)) * (m2 + ReadKey(key, keyIndex + 6));
            sums[2] += (ulong)(m0 + ReadKey(key, keyIndex + 8)) * (m2 + ReadKey(key, keyIndex + 10));
            sums[3] += (ulong)(m0 + ReadKey(key, keyIndex + 12)) * (m2 + ReadKey(key, keyIndex + 14));
            sums[0] += (ulong)(m1 + ReadKey(key, keyIndex + 1)) * (m3 + ReadKey(key, keyIndex + 3));
            sums[1] += (ulong)(m1 + ReadKey(key, keyIndex + 5)) * (m3 + ReadKey(key, keyIndex + 7));
            sums[2] += (ulong)(m1 + ReadKey(key, keyIndex + 9)) * (m3 + ReadKey(key, keyIndex + 11));
            sums[3] += (ulong)(m1 + ReadKey(key, keyIndex + 13)) * (m3 + ReadKey(key, keyIndex + 15));

            keyIndex += MessageUnit / sizeof(uint);
        }

        for (int i = 0; i < NumPasses; i++)
            BinaryPrimitives.WriteUInt64LittleEndian(output[(i * 8)..], sums[i]);
        CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(sums));
    }

    private static void HashAvx2Validated(ReadOnlySpan<byte> key, ReadOnlySpan<byte> message, Span<byte> output)
    {
        Span<Vector256<ulong>> sums = stackalloc Vector256<ulong>[NumPasses];
        sums.Clear();

        ReadOnlySpan<uint> messageWords = MemoryMarshal.Cast<byte, uint>(message);
        ReadOnlySpan<uint> keyWords = MemoryMarshal.Cast<byte, uint>(key);
        int messageIndex = 0;
        for (; messageIndex + 32 <= message.Length; messageIndex += 32)
        {
            Vector256<uint> messageVector = Vector256.LoadUnsafe(
                ref MemoryMarshal.GetReference(messageWords[(messageIndex / sizeof(uint))..]));

            for (int pass = 0; pass < NumPasses; pass++)
            {
                int keyByteIndex = pass * PairStride * 2 * sizeof(uint) + messageIndex;
                Vector256<uint> keyVector = Vector256.LoadUnsafe(
                    ref MemoryMarshal.GetReference(keyWords[(keyByteIndex / sizeof(uint))..]));

                Vector256<uint> left = Avx2.Add(
                    Avx2.Shuffle(messageVector, FirstPairShuffle),
                    Avx2.Shuffle(keyVector, FirstPairShuffle));
                Vector256<uint> right = Avx2.Add(
                    Avx2.Shuffle(messageVector, SecondPairShuffle),
                    Avx2.Shuffle(keyVector, SecondPairShuffle));
                sums[pass] = Avx2.Add(sums[pass], Avx2.Multiply(left, right));
            }
        }

        Span<ulong> scalarSums = stackalloc ulong[NumPasses];
        for (int pass = 0; pass < NumPasses; pass++)
        {
            scalarSums[pass] =
                sums[pass].GetElement(0) +
                sums[pass].GetElement(1) +
                sums[pass].GetElement(2) +
                sums[pass].GetElement(3);
        }

        AddScalarTail(key, message, messageIndex, scalarSums);
        WriteSums(scalarSums, output);
        CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(sums));
        CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(scalarSums));
    }

    private static void HashSse2Validated(ReadOnlySpan<byte> key, ReadOnlySpan<byte> message, Span<byte> output)
    {
        Span<Vector128<ulong>> sums = stackalloc Vector128<ulong>[NumPasses];
        sums.Clear();

        ReadOnlySpan<uint> messageWords = MemoryMarshal.Cast<byte, uint>(message);
        ReadOnlySpan<uint> keyWords = MemoryMarshal.Cast<byte, uint>(key);
        int messageIndex = 0;
        for (; messageIndex + 16 <= message.Length; messageIndex += 16)
        {
            Vector128<uint> messageVector = Vector128.LoadUnsafe(
                ref MemoryMarshal.GetReference(messageWords[(messageIndex / sizeof(uint))..]));

            for (int pass = 0; pass < NumPasses; pass++)
            {
                int keyByteIndex = pass * PairStride * 2 * sizeof(uint) + messageIndex;
                Vector128<uint> keyVector = Vector128.LoadUnsafe(
                    ref MemoryMarshal.GetReference(keyWords[(keyByteIndex / sizeof(uint))..]));

                Vector128<uint> left = Sse2.Add(
                    Sse2.Shuffle(messageVector, FirstPairShuffle),
                    Sse2.Shuffle(keyVector, FirstPairShuffle));
                Vector128<uint> right = Sse2.Add(
                    Sse2.Shuffle(messageVector, SecondPairShuffle),
                    Sse2.Shuffle(keyVector, SecondPairShuffle));
                sums[pass] = Sse2.Add(sums[pass], Sse2.Multiply(left, right));
            }
        }

        Span<ulong> scalarSums = stackalloc ulong[NumPasses];
        for (int pass = 0; pass < NumPasses; pass++)
            scalarSums[pass] = sums[pass].GetElement(0) + sums[pass].GetElement(1);

        AddScalarTail(key, message, messageIndex, scalarSums);
        WriteSums(scalarSums, output);
        CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(sums));
        CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(scalarSums));
    }

    private static void HashAvx512Validated(ReadOnlySpan<byte> key, ReadOnlySpan<byte> message, Span<byte> output)
    {
        Span<Vector512<ulong>> sums = stackalloc Vector512<ulong>[NumPasses];
        sums.Clear();

        ReadOnlySpan<uint> messageWords = MemoryMarshal.Cast<byte, uint>(message);
        ReadOnlySpan<uint> keyWords = MemoryMarshal.Cast<byte, uint>(key);
        int messageIndex = 0;
        for (; messageIndex + 64 <= message.Length; messageIndex += 64)
        {
            Vector512<uint> messageVector = Vector512.LoadUnsafe(
                ref MemoryMarshal.GetReference(messageWords[(messageIndex / sizeof(uint))..]));

            for (int pass = 0; pass < NumPasses; pass++)
            {
                int keyByteIndex = pass * PairStride * 2 * sizeof(uint) + messageIndex;
                Vector512<uint> keyVector = Vector512.LoadUnsafe(
                    ref MemoryMarshal.GetReference(keyWords[(keyByteIndex / sizeof(uint))..]));

                Vector512<uint> left = Avx512F.Add(
                    Avx512F.Shuffle(messageVector, FirstPairShuffle),
                    Avx512F.Shuffle(keyVector, FirstPairShuffle));
                Vector512<uint> right = Avx512F.Add(
                    Avx512F.Shuffle(messageVector, SecondPairShuffle),
                    Avx512F.Shuffle(keyVector, SecondPairShuffle));
                sums[pass] = Avx512F.Add(sums[pass], Avx512F.Multiply(left, right));
            }
        }

        Span<ulong> scalarSums = stackalloc ulong[NumPasses];
        for (int pass = 0; pass < NumPasses; pass++)
        {
            scalarSums[pass] =
                sums[pass].GetElement(0) +
                sums[pass].GetElement(1) +
                sums[pass].GetElement(2) +
                sums[pass].GetElement(3) +
                sums[pass].GetElement(4) +
                sums[pass].GetElement(5) +
                sums[pass].GetElement(6) +
                sums[pass].GetElement(7);
        }

        AddScalarTail(key, message, messageIndex, scalarSums);
        WriteSums(scalarSums, output);
        CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(sums));
        CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(scalarSums));
    }

    private static void AddScalarTail(ReadOnlySpan<byte> key, ReadOnlySpan<byte> message, int messageIndex, Span<ulong> sums)
    {
        for (; messageIndex < message.Length; messageIndex += MessageUnit)
        {
            uint m0 = BinaryPrimitives.ReadUInt32LittleEndian(message[messageIndex..]);
            uint m1 = BinaryPrimitives.ReadUInt32LittleEndian(message[(messageIndex + 4)..]);
            uint m2 = BinaryPrimitives.ReadUInt32LittleEndian(message[(messageIndex + 8)..]);
            uint m3 = BinaryPrimitives.ReadUInt32LittleEndian(message[(messageIndex + 12)..]);

            for (int pass = 0; pass < NumPasses; pass++)
            {
                int keyIndex = pass * PairStride * 2 + messageIndex / sizeof(uint);
                sums[pass] += (ulong)(m0 + ReadKey(key, keyIndex)) * (m2 + ReadKey(key, keyIndex + 2));
                sums[pass] += (ulong)(m1 + ReadKey(key, keyIndex + 1)) * (m3 + ReadKey(key, keyIndex + 3));
            }
        }
    }

    private static void WriteSums(ReadOnlySpan<ulong> sums, Span<byte> output)
    {
        for (int pass = 0; pass < NumPasses; pass++)
            BinaryPrimitives.WriteUInt64LittleEndian(output[(pass * sizeof(ulong))..], sums[pass]);
    }

    private static uint ReadKey(ReadOnlySpan<byte> key, int index) =>
        BinaryPrimitives.ReadUInt32LittleEndian(key[(index * sizeof(uint))..]);
}
