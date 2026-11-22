using System;
using System.Buffers.Binary;
using System.Numerics;
using System.Security.Cryptography;

namespace Poly1305
{
    public sealed class Poly1305 : KeyedHashAlgorithm
    {
        public const int POLY1305_BLOCK_SIZE = 16;
        public const int POLY1305_DIGEST_SIZE = 16;

        private static readonly BigInteger Modulus = (BigInteger.One << 130) - 5;
        private static readonly BigInteger Clamp =
            BigInteger.Parse("0ffffffc0ffffffc0ffffffc0fffffff", System.Globalization.NumberStyles.HexNumber);

        private readonly bool _hasPoly1305Mask;
        private readonly byte[] _mask = new byte[16];
        private byte[] _hash = new byte[16];

        public override bool CanReuseTransform => false;
        public override byte[] Hash => _hash;
        public override int HashSize => POLY1305_DIGEST_SIZE;
        public override int InputBlockSize => POLY1305_BLOCK_SIZE;

        public Poly1305(byte[] key)
        {
            if (key is null) throw new ArgumentNullException(nameof(key));
            if (key.Length != 16 && key.Length != 32)
                throw new ArgumentException("Poly1305 keys must be 16 or 32 bytes.", nameof(key));

            Key = (byte[])key.Clone();
            _hasPoly1305Mask = key.Length == 32;
            if (_hasPoly1305Mask) Array.Copy(key, 16, _mask, 0, 16);
            Initialize();
        }

        public static byte[] Compute(ReadOnlySpan<byte> rKey, ReadOnlySpan<byte> message, ReadOnlySpan<byte> mask)
        {
            if (rKey.Length != 16) throw new ArgumentException("The r key must be 16 bytes.", nameof(rKey));
            if (mask.Length != 16) throw new ArgumentException("The Poly1305 mask must be 16 bytes.", nameof(mask));

            byte[] output = new byte[16];
            Core(rKey, message, output);
            AddLittleEndian(output, mask);
            return output;
        }

        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            if (array is null) throw new ArgumentNullException(nameof(array));
            if (ibStart < 0 || cbSize < 0 || ibStart > array.Length - cbSize)
                throw new ArgumentOutOfRangeException();

            byte[] message = new byte[cbSize];
            Buffer.BlockCopy(array, ibStart, message, 0, cbSize);
            Core(Key.AsSpan(0, 16), message, _hash);
            if (_hasPoly1305Mask) AddLittleEndian(_hash, _mask);
        }

        protected override byte[] HashFinal()
        {
            return (byte[])_hash.Clone();
        }

        public override void Initialize()
        {
            _hash = new byte[16];
        }

        private static void Core(ReadOnlySpan<byte> key, ReadOnlySpan<byte> message, Span<byte> output)
        {
            BigInteger r = new BigInteger(key.ToArray(), isUnsigned: true, isBigEndian: false);
            r &= (BigInteger.One << 128) - 1;
            r &= Clamp;
            BigInteger h = 0;

            int offset = 0;
            while (offset < message.Length)
            {
                int length = Math.Min(16, message.Length - offset);
                byte[] block = message.Slice(offset, length).ToArray();
                BigInteger c = new BigInteger(block, isUnsigned: true, isBigEndian: false);
                c += BigInteger.One << (8 * length);
                h = ((h + c) * r) % Modulus;
                offset += length;
            }

            output.Clear();
            byte[] bytes = h.ToByteArray(isUnsigned: true, isBigEndian: false);
            bytes.AsSpan(0, Math.Min(bytes.Length, 16)).CopyTo(output);
        }

        private static void AddLittleEndian(Span<byte> value, ReadOnlySpan<byte> addend)
        {
            ulong valueLow = BinaryPrimitives.ReadUInt64LittleEndian(value);
            ulong addLow = BinaryPrimitives.ReadUInt64LittleEndian(addend);
            ulong sumLow = unchecked(valueLow + addLow);
            ulong carry = sumLow < valueLow ? 1UL : 0UL;

            ulong valueHigh = BinaryPrimitives.ReadUInt64LittleEndian(value[8..]);
            ulong addHigh = BinaryPrimitives.ReadUInt64LittleEndian(addend[8..]);
            ulong sumHigh = unchecked(valueHigh + addHigh + carry);

            BinaryPrimitives.WriteUInt64LittleEndian(value, sumLow);
            BinaryPrimitives.WriteUInt64LittleEndian(value[8..], sumHigh);
        }
    }
}
