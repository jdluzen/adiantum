using System;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace Poly1305
{
    //https://github.com/google/adiantum/blob/master/benchmark/src/poly1305.c
    public class Poly1305 : KeyedHashAlgorithm
    {
        private uint[] r;
        private readonly uint[][] powers = new uint[4][];
        uint[] h;

        public const int POLY1305_BLOCK_SIZE = 16;
        public const int POLY1305_DIGEST_SIZE = 16;

        public override bool CanReuseTransform => false;

        private byte[] hash;
        public override byte[] Hash => hash;

        public override int HashSize => POLY1305_DIGEST_SIZE;

        public override int InputBlockSize => POLY1305_BLOCK_SIZE;


        public Poly1305(byte[] key)
        {
            Key = key;
            Initialize();
        }

        private static uint get_unaligned_le32(byte[] p, int index)
        {
            //return le32_to_cpu(((le32_unaligned*)p)->v);
            //if (p.Length < 4)
            //    return BitConverter.ToUInt16(p, index);
            //p = p.Skip(index).Take(4).Reverse().ToArray();
            return BitConverter.ToUInt32(p, index);//FIXME: check other endian
        }

        private void poly1305_key_powers()
        {
            uint r0 = r[0], r1 = r[1], r2 = r[2],
                  r3 = r[3], r4 = r[4];
            uint s1 = r1 * 5, s2 = r2 * 5, s3 = r3 * 5, s4 = r4 * 5;
            uint h0 = r0, h1 = r1, h2 = r2, h3 = r3, h4 = r4;
            int i = 0;

            for (; ; )
            {
                ulong d0, d1, d2, d3, d4;

                powers[i] = new uint[9];
                powers[i][0] = h0;
                powers[i][1] = h1;
                powers[i][2] = h1 * 5;
                powers[i][3] = h2;
                powers[i][4] = h2 * 5;
                powers[i][5] = h3;
                powers[i][6] = h3 * 5;
                powers[i][7] = h4;
                powers[i][8] = h4 * 5;

                if (++i == powers.Length)
                    break;

                d0 = ((ulong)h0 * r0) + ((ulong)h1 * s4) + ((ulong)h2 * s3) +

                     ((ulong)h3 * s2) + ((ulong)h4 * s1);
                d1 = ((ulong)h0 * r1) + ((ulong)h1 * r0) + ((ulong)h2 * s4) +

                             ((ulong)h3 * s3) + ((ulong)h4 * s2);
                d2 = ((ulong)h0 * r2) + ((ulong)h1 * r1) + ((ulong)h2 * r0) +

                             ((ulong)h3 * s4) + ((ulong)h4 * s3);
                d3 = ((ulong)h0 * r3) + ((ulong)h1 * r2) + ((ulong)h2 * r1) +

                             ((ulong)h3 * r0) + ((ulong)h4 * s4);
                d4 = ((ulong)h0 * r4) + ((ulong)h1 * r3) + ((ulong)h2 * r2) +

                             ((ulong)h3 * r1) + ((ulong)h4 * r0);

                d1 += (uint)(d0 >> 26);
                h0 = (uint)(d0 & 0x3ffffff);
                d2 += (uint)(d1 >> 26);
                h1 = (uint)(d1 & 0x3ffffff);
                d3 += (uint)(d2 >> 26);
                h2 = (uint)(d2 & 0x3ffffff);
                d4 += (uint)(d3 >> 26);
                h3 = (uint)(d3 & 0x3ffffff);
                h0 += (uint)(d4 >> 26) * 5;
                h4 = (uint)(d4 & 0x3ffffff);
                h1 += h0 >> 26;
                h0 &= 0x3ffffff;
            }
        }

        void poly1305_blocks(byte[] data, int dataStart, int nblocks, uint hibit)
        {
            poly1305_blocks_generic(data, dataStart, nblocks, hibit << 24);
        }

        private void poly1305_blocks_generic(byte[] data, int dataStart, int nblocks, uint hibit)
        {

            uint h0 = h[0], h1 = h[1], h2 = h[2],
                h3 = h[3], h4 = h[4];
            uint r0 = r[0], r1 = r[1], r2 = r[2],
                  r3 = r[3], r4 = r[4];
            uint s1 = r1 * 5, s2 = r2 * 5, s3 = r3 * 5, s4 = r4 * 5;
            ulong d0, d1, d2, d3, d4;

            while (nblocks-- > 0)
            {
                /* Invariants: h0, h2, h3, h4 <= 2^26 - 1; h1 <= 2^26 + 63 */

                /*
                 * Add the next message block to 'h' using five 26-bit limbs,
                 * without doing any carries yet.
                 */
                h0 += (get_unaligned_le32(data, dataStart + 0) >> 0) & 0x3ffffff;
                h1 += (get_unaligned_le32(data, dataStart + 3) >> 2) & 0x3ffffff;
                h2 += (get_unaligned_le32(data, dataStart + 6) >> 4) & 0x3ffffff;
                h3 += (get_unaligned_le32(data, dataStart + 9) >> 6) & 0x3ffffff;
                h4 += (get_unaligned_le32(data, dataStart + 12) >> 8) | hibit;

                /*
                 * Multiply 'h' by 'r', without carrying, and using the property
                 * 2^130 == 5 (mod 2^130 - 5) to keep within the five limbs:
                 *
                 *     r4       r3       r2       r1       r0
                 *  X  h4       h3       h2       h1       h0
                 *     ------ --------------------------------
                 *     h0*r4    h0*r3    h0*r2    h0*r1    h0*r0
                 *     h1*r3    h1*r2    h1*r1    h1*r0    h1*5*r4
                 *     h2*r2    h2*r1    h2*r0    h2*5*r4  h2*5*r3
                 *     h3*r1    h3*r0    h3*5*r4  h3*5*r3  h3*5*r2
                 *     h4*r0    h4*5*r4  h4*5*r3  h4*5*r2  h4*5*r1
                 *
                 * Even if we assume an unclamped key, the greatest possible sum
                 * of products is in the rightmost column (d0) which can be up
                 * to about 2^57.39.  The least is in the leftmost column (d4)
                 * which can only be up to about 2^55.32.  Thus, the sums fit
                 * well within 64-bit integers.
                 */
                d0 = ((ulong)h0 * r0) + ((ulong)h1 * s4) + ((ulong)h2 * s3) +

                     ((ulong)h3 * s2) + ((ulong)h4 * s1);
                d1 = ((ulong)h0 * r1) + ((ulong)h1 * r0) + ((ulong)h2 * s4) +

                     ((ulong)h3 * s3) + ((ulong)h4 * s2);
                d2 = ((ulong)h0 * r2) + ((ulong)h1 * r1) + ((ulong)h2 * r0) +

                     ((ulong)h3 * s4) + ((ulong)h4 * s3);
                d3 = ((ulong)h0 * r3) + ((ulong)h1 * r2) + ((ulong)h2 * r1) +

                     ((ulong)h3 * r0) + ((ulong)h4 * s4);
                d4 = ((ulong)h0 * r4) + ((ulong)h1 * r3) + ((ulong)h2 * r2) +

                     ((ulong)h3 * r1) + ((ulong)h4 * r0);

                /*
                 * Carry h0 => h1 => h2 => h3 => h4 => h0 => h1, assuming no
                 * more than 32 carry bits per limb -- that's guaranteed by all
                 * sums being < 2^58 - 2^32.  d4 is moreover guaranteed to be
                 * < (2^58 - 2^32) / 5, so the needed multiplication with 5 can
                 * be done with 32-bit precision.
                 *
                 * We stop once h1 is reached the second time.  Then, h1 will be
                 * <= 2^26 + 63, and all other limbs will be <= 2^26 - 1.
                 */
                d1 += (uint)(d0 >> 26);
                h0 = (uint)(d0 & 0x3ffffff);
                d2 += (uint)(d1 >> 26);
                h1 = (uint)(d1 & 0x3ffffff);
                d3 += (uint)(d2 >> 26);
                h2 = (uint)(d2 & 0x3ffffff);
                d4 += (uint)(d3 >> 26);
                h3 = (uint)(d3 & 0x3ffffff);
                h0 += (uint)(d4 >> 26) * 5;
                h4 = (uint)(d4 & 0x3ffffff);
                h1 += h0 >> 26;
                h0 &= 0x3ffffff;

                dataStart += POLY1305_BLOCK_SIZE;
            }

            h[0] = h0;
            h[1] = h1;
            h[2] = h2;
            h[3] = h3;
            h[4] = h4;
        }

        private byte[] poly1305_emit_generic()
        {
            byte[] mac = new byte[16];
            uint h0 = h[0], h1 = h[1], h2 = h[2],
                h3 = h[3], h4 = h[4];
            uint g0, g1, g2, g3, g4;
            uint mask;

            /* fully carry h */
            h2 += (h1 >> 26); h1 &= 0x3ffffff;
            h3 += (h2 >> 26); h2 &= 0x3ffffff;
            h4 += (h3 >> 26); h3 &= 0x3ffffff;
            h0 += (h4 >> 26) * 5; h4 &= 0x3ffffff;
            h1 += (h0 >> 26); h0 &= 0x3ffffff;

            /* compute h + -p */
            g0 = h0 + 5;
            g1 = h1 + (g0 >> 26); g0 &= 0x3ffffff;
            g2 = h2 + (g1 >> 26); g1 &= 0x3ffffff;
            g3 = h3 + (g2 >> 26); g2 &= 0x3ffffff;
            g4 = h4 + (g3 >> 26) - (1 << 26); g3 &= 0x3ffffff;

            /* select h if h < p, or h + -p if h >= p */
            mask = (g4 >> 31) - 1;
            g0 &= mask;
            g1 &= mask;
            g2 &= mask;
            g3 &= mask;
            g4 &= mask;
            mask = ~mask;
            h0 = (h0 & mask) | g0;
            h1 = (h1 & mask) | g1;
            h2 = (h2 & mask) | g2;
            h3 = (h3 & mask) | g3;
            h4 = (h4 & mask) | g4;

            /* h = h % (2^128) */
            Buffer.BlockCopy(cpu_to_le32((h0 >> 0) | (h1 << 26)), 0, mac, 0, 4);
            Buffer.BlockCopy(cpu_to_le32((h1 >> 6) | (h2 << 20)), 0, mac, 4, 4);
            Buffer.BlockCopy(cpu_to_le32((h2 >> 12) | (h3 << 14)), 0, mac, 8, 4);
            Buffer.BlockCopy(cpu_to_le32((h3 >> 18) | (h4 << 8)), 0, mac, 12, 4);

            //   out->w32[0] = cpu_to_le32((h0 >> 0) | (h1 << 26));
            //out->w32[1] = cpu_to_le32((h1 >> 6) | (h2 << 20));
            //out->w32[2] = cpu_to_le32((h2 >> 12) | (h3 << 14));
            //out->w32[3] = cpu_to_le32((h3 >> 18) | (h4 << 8));

            return mac;
        }

        private static byte[] cpu_to_le32(uint v)
        {
            byte[] bits = BitConverter.GetBytes(v);

            //Array.Reverse(bits);//FIXME

            return bits;
        }

        void poly1305_tail(byte[] src, int srcIndex, int srclen)
        {

            poly1305_blocks(src, srcIndex, srclen / POLY1305_BLOCK_SIZE, 1);

            if (srclen % POLY1305_BLOCK_SIZE != 0)
            {
                byte[] block = new byte[POLY1305_BLOCK_SIZE];

                srcIndex += srclen - (srclen % POLY1305_BLOCK_SIZE);
                srclen %= POLY1305_BLOCK_SIZE;
                Buffer.BlockCopy(src, srcIndex, block, 0, srclen);
                block[srclen++] = 1;
                //memset(&block[srclen], 0, sizeof(block) - srclen);
                poly1305_blocks(block, 0, 1, 0);
            }
        }

        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            poly1305_tail(array, ibStart, cbSize);

            //if (array.Length < POLY1305_BLOCK_SIZE)
            //{
            //    byte[] temp = new byte[POLY1305_BLOCK_SIZE];
            //    Buffer.BlockCopy(array, ibStart, temp, 0, cbSize);
            //    ibStart = 0;
            //    array = temp;
            //}

            //poly1305_blocks_generic(array, ibStart, 1, 1);
        }

        protected override byte[] HashFinal()
        {
            return hash = poly1305_emit_generic();
        }

        public override void Initialize()
        {
            r = new uint[5];
            h = new uint[5];
            /* Clamp the Poly1305 key and split it into five 26-bit limbs */
            uint temp = get_unaligned_le32(Key, 0);
            r[0] = temp >> 0 & 0x3ffffff;//this is broken?
            r[1] = (get_unaligned_le32(Key, 3) >> 2) & 0x3ffff03;
            r[2] = (get_unaligned_le32(Key, 6) >> 4) & 0x3ffc0ff;
            r[3] = (get_unaligned_le32(Key, 9) >> 6) & 0x3f03fff;
            r[4] = (get_unaligned_le32(Key, 12) >> 8) & 0x00fffff;

            /* Precompute key powers */
            poly1305_key_powers();
        }
    }
}
