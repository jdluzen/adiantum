using System;
using System.Buffers.Binary;
using System.Security.Cryptography;

namespace DZen.Adiantum.Internal;

// Fixed-width 5x26-bit Poly1305 arithmetic. Although arithmetic and final
// reduction avoid secret-dependent branches, the managed runtime/JIT does not
// provide a formal constant-time guarantee.
internal static class Poly1305
{
    internal static void Process(ReadOnlySpan<byte> key, ReadOnlySpan<byte> message, Span<byte> output)
    {
        using StreamingState state = new(key);
        state.Update(message);
        state.Finish(output);
    }

    internal static void HashWithoutFinalization(
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> message,
        Span<byte> output)
    {
        using StreamingState state = new(key);
        state.Update(message);
        state.Finish(output);
    }

    internal sealed class StreamingState : IDisposable
    {
        private const uint LimbMask = (1U << 26) - 1;
        private readonly byte[] _buffer = new byte[16];
        private uint _r0, _r1, _r2, _r3, _r4;
        private uint _s1, _s2, _s3, _s4;
        private uint _h0, _h1, _h2, _h3, _h4;
        private int _bufferLength;
        private bool _finished;

        internal StreamingState(ReadOnlySpan<byte> key)
        {
            if (key.Length != 16)
                throw new ArgumentException("A Poly1305 key must be 16 bytes.", nameof(key));

            _r0 = BinaryPrimitives.ReadUInt32LittleEndian(key) & 0x3ffffff;
            _r1 = (BinaryPrimitives.ReadUInt32LittleEndian(key.Slice(3)) >> 2) & 0x3ffff03;
            _r2 = (BinaryPrimitives.ReadUInt32LittleEndian(key.Slice(6)) >> 4) & 0x3ffc0ff;
            _r3 = (BinaryPrimitives.ReadUInt32LittleEndian(key.Slice(9)) >> 6) & 0x3f03fff;
            _r4 = (BinaryPrimitives.ReadUInt32LittleEndian(key.Slice(12)) >> 8) & 0x00fffff;
            _s1 = _r1 * 5;
            _s2 = _r2 * 5;
            _s3 = _r3 * 5;
            _s4 = _r4 * 5;
        }

        internal void Update(ReadOnlySpan<byte> data)
        {
            ThrowIfFinished();

            if (_bufferLength != 0)
            {
                int copied = Math.Min(16 - _bufferLength, data.Length);
                data.Slice(0, copied).CopyTo(_buffer.AsSpan(_bufferLength));
                _bufferLength += copied;
                data = data.Slice(copied);

                if (_bufferLength == 16)
                {
                    ProcessBlock(_buffer, fullBlock: true);
                    CryptographicOperations.ZeroMemory(_buffer);
                    _bufferLength = 0;
                }
            }

            while (data.Length >= 16)
            {
                ProcessBlock(data.Slice(0, 16), fullBlock: true);
                data = data.Slice(16);
            }

            if (!data.IsEmpty)
            {
                data.CopyTo(_buffer);
                _bufferLength = data.Length;
            }
        }

        internal void Finish(Span<byte> output)
        {
            ThrowIfFinished();
            if (output.Length != 16)
                throw new ArgumentException("A Poly1305 output must be 16 bytes.", nameof(output));

            if (_bufferLength != 0)
            {
                _buffer[_bufferLength] = 1;
                _buffer.AsSpan(_bufferLength + 1).Clear();
                ProcessBlock(_buffer, fullBlock: false);
            }

            ReduceAndWrite(output);
            ClearSensitiveState();
            _finished = true;
        }

        public void Dispose()
        {
            ClearSensitiveState();
            _finished = true;
        }

        private void ProcessBlock(ReadOnlySpan<byte> block, bool fullBlock)
        {
            uint t0 = BinaryPrimitives.ReadUInt32LittleEndian(block);
            uint t1 = BinaryPrimitives.ReadUInt32LittleEndian(block.Slice(4));
            uint t2 = BinaryPrimitives.ReadUInt32LittleEndian(block.Slice(8));
            uint t3 = BinaryPrimitives.ReadUInt32LittleEndian(block.Slice(12));

            _h0 += t0 & LimbMask;
            _h1 += ((t0 >> 26) | (t1 << 6)) & LimbMask;
            _h2 += ((t1 >> 20) | (t2 << 12)) & LimbMask;
            _h3 += ((t2 >> 14) | (t3 << 18)) & LimbMask;
            _h4 += (t3 >> 8) | (fullBlock ? (1U << 24) : 0U);

            ulong d0 = (ulong)_h0 * _r0 + (ulong)_h1 * _s4 +
                (ulong)_h2 * _s3 + (ulong)_h3 * _s2 + (ulong)_h4 * _s1;
            ulong d1 = (ulong)_h0 * _r1 + (ulong)_h1 * _r0 +
                (ulong)_h2 * _s4 + (ulong)_h3 * _s3 + (ulong)_h4 * _s2;
            ulong d2 = (ulong)_h0 * _r2 + (ulong)_h1 * _r1 +
                (ulong)_h2 * _r0 + (ulong)_h3 * _s4 + (ulong)_h4 * _s3;
            ulong d3 = (ulong)_h0 * _r3 + (ulong)_h1 * _r2 +
                (ulong)_h2 * _r1 + (ulong)_h3 * _r0 + (ulong)_h4 * _s4;
            ulong d4 = (ulong)_h0 * _r4 + (ulong)_h1 * _r3 +
                (ulong)_h2 * _r2 + (ulong)_h3 * _r1 + (ulong)_h4 * _r0;

            ulong carry = d0 >> 26;
            _h0 = (uint)d0 & LimbMask;
            d1 += carry;
            carry = d1 >> 26;
            _h1 = (uint)d1 & LimbMask;
            d2 += carry;
            carry = d2 >> 26;
            _h2 = (uint)d2 & LimbMask;
            d3 += carry;
            carry = d3 >> 26;
            _h3 = (uint)d3 & LimbMask;
            d4 += carry;
            carry = d4 >> 26;
            _h4 = (uint)d4 & LimbMask;
            _h0 += (uint)(carry * 5);
            carry = _h0 >> 26;
            _h0 &= LimbMask;
            _h1 += (uint)carry;
        }

        private void ReduceAndWrite(Span<byte> output)
        {
            uint carry = _h1 >> 26;
            _h1 &= LimbMask;
            _h2 += carry;
            carry = _h2 >> 26;
            _h2 &= LimbMask;
            _h3 += carry;
            carry = _h3 >> 26;
            _h3 &= LimbMask;
            _h4 += carry;
            carry = _h4 >> 26;
            _h4 &= LimbMask;
            _h0 += carry * 5;
            carry = _h0 >> 26;
            _h0 &= LimbMask;
            _h1 += carry;

            uint g0 = _h0 + 5;
            carry = g0 >> 26;
            g0 &= LimbMask;
            uint g1 = _h1 + carry;
            carry = g1 >> 26;
            g1 &= LimbMask;
            uint g2 = _h2 + carry;
            carry = g2 >> 26;
            g2 &= LimbMask;
            uint g3 = _h3 + carry;
            carry = g3 >> 26;
            g3 &= LimbMask;
            uint g4 = unchecked(_h4 + carry - (1U << 26));

            uint useG = (g4 >> 31) - 1;
            uint useH = ~useG;
            _h0 = (_h0 & useH) | (g0 & useG);
            _h1 = (_h1 & useH) | (g1 & useG);
            _h2 = (_h2 & useH) | (g2 & useG);
            _h3 = (_h3 & useH) | (g3 & useG);
            _h4 = (_h4 & useH) | (g4 & useG);

            uint w0 = _h0 | (_h1 << 26);
            uint w1 = (_h1 >> 6) | (_h2 << 20);
            uint w2 = (_h2 >> 12) | (_h3 << 14);
            uint w3 = (_h3 >> 18) | (_h4 << 8);
            BinaryPrimitives.WriteUInt32LittleEndian(output, w0);
            BinaryPrimitives.WriteUInt32LittleEndian(output.Slice(4), w1);
            BinaryPrimitives.WriteUInt32LittleEndian(output.Slice(8), w2);
            BinaryPrimitives.WriteUInt32LittleEndian(output.Slice(12), w3);
        }

        private void ThrowIfFinished()
        {
            if (_finished)
                throw new InvalidOperationException("The Poly1305 state has already been finalized or disposed.");
        }

        private void ClearSensitiveState()
        {
            _r0 = _r1 = _r2 = _r3 = _r4 = 0;
            _s1 = _s2 = _s3 = _s4 = 0;
            _h0 = _h1 = _h2 = _h3 = _h4 = 0;
            _bufferLength = 0;
            CryptographicOperations.ZeroMemory(_buffer);
        }
    }
}
