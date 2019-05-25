using System;
using System.Security.Cryptography;

namespace NH
{
    //https://github.com/google/adiantum/blob/master/benchmark/src/nh.c
    public class Nh : HashAlgorithm
    {
        private const int NH_PAIR_STRIDE = 2;
        private const int NH_NUM_STRIDES = 64;
        private const int NH_NUM_PASSES = 4;

        private const int NH_MESSAGE_DWORDS = (NH_PAIR_STRIDE * 2 * NH_NUM_STRIDES);

        private const int NH_KEY_DWORDS = (NH_MESSAGE_DWORDS + NH_PAIR_STRIDE * 2 * (NH_NUM_PASSES - 1));

        private const int NH_MESSAGE_UNIT = (NH_PAIR_STRIDE * 8);
        private const int NH_MESSAGE_BYTES = (NH_MESSAGE_DWORDS * 4);
        private const int NH_KEY_BYTES = (NH_KEY_DWORDS * 4);
        private const int NH_HASH_BYTES = (NH_NUM_PASSES * 8);

        public uint[] Key { get; private set; }

        private byte[] hash;
        public override byte[] Hash => hash;
        public override int HashSize => NH_HASH_BYTES;
        public override bool CanReuseTransform => false;

        public int KeySize => NH_KEY_BYTES;

        public Nh(byte[] key)
        {
            Initialize(key);
        }

        public void Initialize(byte[] key)
        {
            Key = new uint[NH_KEY_DWORDS];
            for (int i = 0; i < Key.Length; i++)
            {
                Key[i] = get_unaligned_le32(key, i * sizeof(uint));
            }
        }

        public override void Initialize()
        {
        }


        private static uint get_unaligned_le32(byte[] p, int index)
        {
            //return le32_to_cpu(((le32_unaligned*)p)->v);
            return BitConverter.ToUInt32(p, index);//FIXME: check other endian
        }

        private static void put_unaligned_le64(ulong v, byte[] p, int index)
        {
            //((le64_unaligned *)p)->v = cpu_to_le64(v);
            byte[] bytes = BitConverter.GetBytes(v);
            Buffer.BlockCopy(bytes, 0, p, index, bytes.Length);
            //Array.Copy(bytes, 0, p, index, bytes.Length);
        }

        static ulong nhpass(uint[] key, int keyIndex, uint[] message, int messageIndex, int message_dwords)
        {
            ulong sum = 0;
            int i, j;

            for (i = 0; i < message_dwords; i += NH_PAIR_STRIDE * 2)
            {
                for (j = i; j < i + NH_PAIR_STRIDE; j++)
                {
                    int thisLoopKeyIndex = keyIndex + j;
                    int thisLoopMessageIndex = messageIndex + j;
                    uint l = key[thisLoopKeyIndex] + message[thisLoopMessageIndex];
                    uint r = key[thisLoopKeyIndex + NH_PAIR_STRIDE] +
                        message[thisLoopMessageIndex + NH_PAIR_STRIDE];

                    sum += (ulong)l * (ulong)r;
                }
            }

            return sum;
        }

        protected void HashCore2(byte[] array, int ibStart, int cbSize)
        {
            hash = new byte[NH_HASH_BYTES];
            uint[] message_vec = new uint[NH_MESSAGE_DWORDS];
            ulong[] hash_vec = new ulong[NH_NUM_PASSES];
            int message_dwords = cbSize / sizeof(uint);
            int i;

            //ASSERT(message_len % NH_MESSAGE_UNIT == 0);

            for (i = 0; i < message_dwords; i++)
                message_vec[i] =
                    get_unaligned_le32(array, i * sizeof(uint));

            for (i = 0; i < NH_NUM_PASSES; i++)
                hash_vec[i] = nhpass(Key, i * NH_PAIR_STRIDE * 2,
                             message_vec, 0, message_dwords);

            for (i = 0; i < hash_vec.Length; i++)
                put_unaligned_le64(hash_vec[i], hash, i * sizeof(ulong));
        }

        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            ulong[] sums = new ulong[] { 0, 0, 0, 0 };
            hash = new byte[NH_HASH_BYTES];

            //BUILD_BUG_ON(NH_PAIR_STRIDE != 2);
            //BUILD_BUG_ON(NH_NUM_PASSES != 4);

            int keyIndex = 0;

            while (cbSize > 0)
            {
                uint m0 = get_unaligned_le32(array, ibStart + 0);
                uint m1 = get_unaligned_le32(array, ibStart + 4);
                uint m2 = get_unaligned_le32(array, ibStart + 8);
                uint m3 = get_unaligned_le32(array, ibStart + 12);

                sums[0] += (ulong)(m0 + Key[keyIndex + 0]) * (m2 + Key[keyIndex + 2]);
                sums[1] += (ulong)(m0 + Key[keyIndex + 4]) * (m2 + Key[keyIndex + 6]);
                sums[2] += (ulong)(m0 + Key[keyIndex + 8]) * (m2 + Key[keyIndex + 10]);
                sums[3] += (ulong)(m0 + Key[keyIndex + 12]) * (m2 + Key[keyIndex + 14]);
                sums[0] += (ulong)(m1 + Key[keyIndex + 1]) * (m3 + Key[keyIndex + 3]);
                sums[1] += (ulong)(m1 + Key[keyIndex + 5]) * (m3 + Key[keyIndex + 7]);
                sums[2] += (ulong)(m1 + Key[keyIndex + 9]) * (m3 + Key[keyIndex + 11]);
                sums[3] += (ulong)(m1 + Key[keyIndex + 13]) * (m3 + Key[keyIndex + 15]);

                keyIndex += NH_MESSAGE_UNIT / sizeof(uint);
                ibStart += NH_MESSAGE_UNIT;
                cbSize -= NH_MESSAGE_UNIT;
            }

            put_unaligned_le64(sums[0], hash, 0);
            put_unaligned_le64(sums[1], hash, 8);
            put_unaligned_le64(sums[2], hash, 16);
            put_unaligned_le64(sums[3], hash, 24);
        }

        protected override byte[] HashFinal()
        {
            return Hash;
        }
    }
}
