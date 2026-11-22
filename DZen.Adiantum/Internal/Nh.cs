using System;
using System.Buffers.Binary;

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

    internal static void Hash(ReadOnlySpan<byte> key, ReadOnlySpan<byte> message, Span<byte> output)
    {
        if (key.Length != KeyBytes) throw new ArgumentException("Invalid NH key length.", nameof(key));
        if (message.Length == 0 || message.Length > MessageBytes || (message.Length & 15) != 0)
            throw new ArgumentException("NH message must be non-empty and a multiple of 16 bytes.", nameof(message));
        if (output.Length != HashBytes) throw new ArgumentException("Invalid NH output length.", nameof(output));

        Span<ulong> sums = stackalloc ulong[NumPasses];
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
    }

    private static uint ReadKey(ReadOnlySpan<byte> key, int index) =>
        BinaryPrimitives.ReadUInt32LittleEndian(key[(index * sizeof(uint))..]);
}
