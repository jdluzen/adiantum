using System;
using System.Buffers.Binary;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace DZen.Adiantum.Internal;

internal static class XChaCha12
{
    private static uint RotateLeft(uint value, int bits) =>
        (value << bits) | (value >> (32 - bits));

    private static void QuarterRound(Span<uint> state, int a, int b, int c, int d)
    {
        state[a] += state[b]; state[d] ^= state[a]; state[d] = RotateLeft(state[d], 16);
        state[c] += state[d]; state[b] ^= state[c]; state[b] = RotateLeft(state[b], 12);
        state[a] += state[b]; state[d] ^= state[a]; state[d] = RotateLeft(state[d], 8);
        state[c] += state[d]; state[b] ^= state[c]; state[b] = RotateLeft(state[b], 7);
    }

    private static void HChaCha(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce16, Span<byte> output)
    {
        Span<uint> state = stackalloc uint[16];
        state[0] = 0x61707865; state[1] = 0x3320646e; state[2] = 0x79622d32; state[3] = 0x6b206574;
        for (int i = 0; i < 8; i++) state[4 + i] = BinaryPrimitives.ReadUInt32LittleEndian(key[(i * 4)..]);
        for (int i = 0; i < 4; i++) state[12 + i] = BinaryPrimitives.ReadUInt32LittleEndian(nonce16[(i * 4)..]);

        for (int i = 0; i < 6; i++)
        {
            QuarterRound(state, 0, 4, 8, 12);
            QuarterRound(state, 1, 5, 9, 13);
            QuarterRound(state, 2, 6, 10, 14);
            QuarterRound(state, 3, 7, 11, 15);
            QuarterRound(state, 0, 5, 10, 15);
            QuarterRound(state, 1, 6, 11, 12);
            QuarterRound(state, 2, 7, 8, 13);
            QuarterRound(state, 3, 4, 9, 14);
        }

        for (int i = 0; i < 4; i++) BinaryPrimitives.WriteUInt32LittleEndian(output[(i * 4)..], state[i]);
        for (int i = 0; i < 4; i++) BinaryPrimitives.WriteUInt32LittleEndian(output[((4 + i) * 4)..], state[12 + i]);
        CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(state));
    }

    private static void ChaChaBlock(ReadOnlySpan<byte> subkey, ulong counter, ReadOnlySpan<byte> nonce8, Span<byte> output)
    {
        Span<uint> state = stackalloc uint[16];
        Span<uint> initial = stackalloc uint[16];
        initial[0] = 0x61707865; initial[1] = 0x3320646e; initial[2] = 0x79622d32; initial[3] = 0x6b206574;
        for (int i = 0; i < 8; i++) initial[4 + i] = BinaryPrimitives.ReadUInt32LittleEndian(subkey[(i * 4)..]);
        initial[12] = unchecked((uint)counter);
        initial[13] = (uint)(counter >> 32);
        initial[14] = BinaryPrimitives.ReadUInt32LittleEndian(nonce8);
        initial[15] = BinaryPrimitives.ReadUInt32LittleEndian(nonce8[4..]);
        initial.CopyTo(state);

        for (int i = 0; i < 6; i++)
        {
            QuarterRound(state, 0, 4, 8, 12);
            QuarterRound(state, 1, 5, 9, 13);
            QuarterRound(state, 2, 6, 10, 14);
            QuarterRound(state, 3, 7, 11, 15);
            QuarterRound(state, 0, 5, 10, 15);
            QuarterRound(state, 1, 6, 11, 12);
            QuarterRound(state, 2, 7, 8, 13);
            QuarterRound(state, 3, 4, 9, 14);
        }

        for (int i = 0; i < 16; i++)
            BinaryPrimitives.WriteUInt32LittleEndian(output[(i * 4)..], state[i] + initial[i]);
        CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(state));
        CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(initial));
    }

    internal static void Crypt(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce24, Span<byte> destination, ulong startingBlock = 0)
    {
        if (key.Length != 32) throw new ArgumentException("An XChaCha12 key must be 32 bytes.", nameof(key));
        if (nonce24.Length != 24) throw new ArgumentException("An XChaCha12 nonce must be 24 bytes.", nameof(nonce24));

        Span<byte> subkey = stackalloc byte[32];
        Span<byte> block = stackalloc byte[64];
        try
        {
            HChaCha(key, nonce24[..16], subkey);
            ulong counter = startingBlock;
            ReadOnlySpan<byte> nonce8 = nonce24[16..24];
            int offset = 0;
            while (offset < destination.Length)
            {
                ChaChaBlock(subkey, counter, nonce8, block);
                int length = Math.Min(64, destination.Length - offset);
                for (int i = 0; i < length; i++)
                    destination[offset + i] ^= block[i];
                offset += length;
                counter++;
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(subkey);
            CryptographicOperations.ZeroMemory(block);
        }
    }
}
