using System;
using System.Numerics;
using Poly1305Impl = DZen.Adiantum.Internal.Poly1305;

namespace DZen.Adiantum.Test;

internal static class Poly1305FocusedTests
{
    private static readonly BigInteger Modulus = (BigInteger.One << 130) - 5;
    private static readonly BigInteger Clamp = BigInteger.Parse(
        "0ffffffc0ffffffc0ffffffc0fffffff",
        System.Globalization.NumberStyles.HexNumber);

    internal static void Run()
    {
        TestKnownAnswer();
        TestSignedLengthCase();
        TestFragmentBoundaries();
        TestRandomizedOracle();
        TestStateLifecycle();
    }

    private static void TestKnownAnswer()
    {
        byte[] key = Convert.FromHexString("85d6be7857556d337f4452fe42d506a8");
        byte[] message = System.Text.Encoding.ASCII.GetBytes("Cryptographic Forum Research Group");
        byte[] expected = Convert.FromHexString("a7039d36354384c8776c94ffcab7318d");
        byte[] actual = new byte[16];

        Poly1305Impl.Process(key, message, actual);
        AssertEqual(expected, actual, "RFC Poly1305 accumulator vector");
    }

    private static void TestSignedLengthCase()
    {
        byte[] key = new byte[16];
        key[0] = 0x80;
        byte[] message = new byte[1];
        byte[] expected = Convert.FromHexString("00800000000000000000000000000000");
        byte[] actual = new byte[16];

        BigInteger oracle = ComputeOracle(key, message);
        if (oracle.ToByteArray(isUnsigned: true, isBigEndian: false).Length != 2 ||
            oracle.ToByteArray(isUnsigned: false, isBigEndian: false).Length != 3)
            throw new InvalidOperationException("The crafted Poly1305 accumulator did not exercise signed-length encoding.");

        Poly1305Impl.Process(key, message, actual);
        AssertEqual(expected, actual, "signed-length accumulator case");
        AssertEqual(OracleBytes(oracle), actual, "signed-length BigInteger oracle");
    }

    private static void TestFragmentBoundaries()
    {
        int[] lengths = { 0, 1, 14, 15, 16, 17, 30, 31, 32, 33, 47, 48, 49, 63, 64, 65, 127, 128, 129, 1023, 1024, 1025 };
        int[] fragmentSizes = { 1, 2, 15, 16, 17, 31, 32 };
        Random random = new(0x501305);

        foreach (int length in lengths)
        {
            byte[] key = new byte[16];
            byte[] message = new byte[length];
            random.NextBytes(key);
            random.NextBytes(message);
            byte[] expected = OracleBytes(ComputeOracle(key, message));

            foreach (int fragmentSize in fragmentSizes)
            {
                byte[] actual = new byte[16];
                using Poly1305Impl.StreamingState state = new(key);
                for (int offset = 0; offset < message.Length; offset += fragmentSize)
                    state.Update(message.AsSpan(offset, Math.Min(fragmentSize, message.Length - offset)));
                state.Finish(actual);
                AssertEqual(expected, actual, $"fragment size {fragmentSize}, message length {length}");
            }
        }
    }

    private static void TestRandomizedOracle()
    {
        Random random = new(0x1305C0DE);
        for (int iteration = 0; iteration < 2000; iteration++)
        {
            byte[] key = new byte[16];
            byte[] message = new byte[random.Next(0, 2049)];
            random.NextBytes(key);
            random.NextBytes(message);

            byte[] expected = OracleBytes(ComputeOracle(key, message));
            byte[] actual = new byte[16];
            Poly1305Impl.Process(key, message, actual);
            AssertEqual(expected, actual, $"randomized Process iteration {iteration}");

            byte[] streamed = new byte[16];
            using (Poly1305Impl.StreamingState state = new(key))
            {
                int offset = 0;
                while (offset < message.Length)
                {
                    int count = Math.Min(random.Next(1, 34), message.Length - offset);
                    state.Update(message.AsSpan(offset, count));
                    offset += count;
                }

                state.Finish(streamed);
            }
            AssertEqual(expected, streamed, $"randomized streaming iteration {iteration}");

            byte[] compatible = new byte[16];
            Poly1305Impl.HashWithoutFinalization(key, message, compatible);
            AssertEqual(expected, compatible, $"HashWithoutFinalization iteration {iteration}");
        }
    }

    private static void TestStateLifecycle()
    {
        byte[] key = new byte[16];
        key[0] = 0x80;
        byte[] message = { 1, 2, 3 };
        byte[] expected = new byte[16];
        byte[] actual = new byte[16];
        Poly1305Impl.Process(key, message, expected);

        using Poly1305Impl.StreamingState state = new(key);
        state.Update(message.AsSpan(0, 1));
        state.Update(ReadOnlySpan<byte>.Empty);
        state.Update(message.AsSpan(1));
        state.Finish(actual);
        AssertEqual(expected, actual, "empty update");
        AssertFinished(() => state.Update(message));
        AssertFinished(() => state.Finish(actual));

        Poly1305Impl.StreamingState disposed = new(key);
        disposed.Dispose();
        AssertFinished(() => disposed.Update(message));
        AssertFinished(() => disposed.Finish(actual));
    }

    private static void AssertFinished(Action action)
    {
        try
        {
            action();
        }
        catch (InvalidOperationException)
        {
            return;
        }

        throw new InvalidOperationException("A finalized or disposed Poly1305 state was reused.");
    }

    private static BigInteger ComputeOracle(byte[] key, byte[] message)
    {
        BigInteger r = new BigInteger(key, isUnsigned: true, isBigEndian: false) & Clamp;
        BigInteger h = BigInteger.Zero;
        for (int offset = 0; offset < message.Length;)
        {
            int count = Math.Min(16, message.Length - offset);
            BigInteger block = new BigInteger(
                message.AsSpan(offset, count),
                isUnsigned: true,
                isBigEndian: false);
            block += BigInteger.One << (count * 8);
            h = ((h + block) * r) % Modulus;
            offset += count;
        }
        return h;
    }

    private static byte[] OracleBytes(BigInteger value)
    {
        byte[] output = new byte[16];
        value.ToByteArray(isUnsigned: true, isBigEndian: false)
            .AsSpan(0, Math.Min(16, value.ToByteArray(isUnsigned: true, isBigEndian: false).Length))
            .CopyTo(output);
        return output;
    }

    private static void AssertEqual(byte[] expected, byte[] actual, string description)
    {
        if (!expected.AsSpan().SequenceEqual(actual))
            throw new InvalidOperationException(
                $"Poly1305 focused test failed ({description}): expected {Convert.ToHexString(expected)}, actual {Convert.ToHexString(actual)}.");
    }
}
