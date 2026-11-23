using DZen.Adiantum.Internal;
using System;
using System.Buffers.Binary;
using System.Text.Json;

namespace DZen.Adiantum.Test;

internal static class Program
{
    private static void Main()
    {
        TestNh();
        string[] simdPaths = TestNhVectorized();
        TestPoly1305();
        Poly1305FocusedTests.Run();
        TestXChaCha();
        TestAdiantum();
        TestLargeInputs();
        string simdResult = simdPaths.Length == 0
            ? "no x86 SIMD paths were available"
            : $"NH SIMD comparisons passed for: {string.Join(", ", simdPaths)}";
        Console.WriteLine($"Reference vectors passed; {simdResult}.");
    }

    private static void TestNh()
    {
        using JsonDocument document = JsonDocument.Parse(System.IO.File.ReadAllText(
            System.IO.Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "..", "test_vectors", "NH", "NH.json")));
        foreach (JsonElement vector in document.RootElement.EnumerateArray())
        {
            byte[] key = Convert.FromHexString(vector.GetProperty("input").GetProperty("key_hex").GetString()!);
            byte[] message = Convert.FromHexString(vector.GetProperty("input").GetProperty("message_hex").GetString()!);
            byte[] expected = Convert.FromHexString(vector.GetProperty("hash_hex").GetString()!);
            byte[] actual = new byte[32];
            Nh.Hash(key, message, actual);
            byte[] legacy = new NH.Nh(key).ComputeHash(message);
            string description = vector.GetProperty("description").GetString()!;
            if (!legacy.AsSpan().SequenceEqual(expected))
                throw new InvalidOperationException($"Legacy NH vector failed: {description}");
            if (!actual.AsSpan().SequenceEqual(expected))
                throw new InvalidOperationException($"NH vector failed: description={description}, expected={Convert.ToHexString(expected).ToLowerInvariant()}, modern={Convert.ToHexString(actual).ToLowerInvariant()}, legacy={Convert.ToHexString(legacy).ToLowerInvariant()}");
        }
    }

    private static string[] TestNhVectorized()
    {
        byte[] key = new byte[Nh.KeyBytes];
        byte[] message = new byte[Nh.MessageBytes];
        byte[] scalar = new byte[Nh.HashBytes];
        Random random = new(0x4E48);
        System.Collections.Generic.List<string> testedPaths = new();
        random.NextBytes(key);

        for (int length = Nh.MessageUnit; length <= Nh.MessageBytes; length += Nh.MessageUnit)
        {
            random.NextBytes(message.AsSpan(0, length));
            Nh.HashScalar(key, message.AsSpan(0, length), scalar);

            if (System.Runtime.Intrinsics.X86.Sse2.IsSupported)
                VerifyNhPath("SSE2", Nh.HashSse2, key, message, length, scalar, testedPaths);
            if (System.Runtime.Intrinsics.X86.Avx2.IsSupported)
                VerifyNhPath("AVX2", Nh.HashAvx2, key, message, length, scalar, testedPaths);
            if (System.Runtime.Intrinsics.X86.Avx512F.IsSupported)
                VerifyNhPath("AVX-512F", Nh.HashAvx512, key, message, length, scalar, testedPaths);
        }

        return testedPaths.ToArray();
    }

    private delegate void NhHash(ReadOnlySpan<byte> key, ReadOnlySpan<byte> message, Span<byte> output);

    private static void VerifyNhPath(
        string pathName,
        NhHash hash,
        byte[] key,
        byte[] message,
        int length,
        byte[] scalar,
        System.Collections.Generic.List<string> testedPaths)
    {
        byte[] vectorized = new byte[Nh.HashBytes];
        hash(key, message.AsSpan(0, length), vectorized);
        if (!scalar.AsSpan().SequenceEqual(vectorized))
            throw new InvalidOperationException($"NH scalar/{pathName} mismatch at {length} bytes.");
        if (!testedPaths.Contains(pathName))
            testedPaths.Add(pathName);
    }

    private static void TestPoly1305()
    {
        using JsonDocument document = JsonDocument.Parse(System.IO.File.ReadAllText(
            System.IO.Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "..", "test_vectors", "Poly1305", "Poly1305.json")));
        foreach (JsonElement vector in document.RootElement.EnumerateArray())
        {
            byte[] key = Convert.FromHexString(vector.GetProperty("input").GetProperty("key_hex").GetString()!);
            byte[] message = Convert.FromHexString(vector.GetProperty("input").GetProperty("message_hex").GetString()!);
            byte[] expected = Convert.FromHexString(vector.GetProperty("mac_hex").GetString()!);
            byte[] mask = Convert.FromHexString(vector.GetProperty("input").GetProperty("mask_hex").GetString()!);
            byte[] actual = new byte[16];
            Poly1305.Process(key, message, actual);
            ulong low = BinaryPrimitives.ReadUInt64LittleEndian(actual);
            ulong high = BinaryPrimitives.ReadUInt64LittleEndian(actual.AsSpan(8));
            ulong maskLow = BinaryPrimitives.ReadUInt64LittleEndian(mask);
            ulong maskHigh = BinaryPrimitives.ReadUInt64LittleEndian(mask.AsSpan(8));
            ulong sumLow = unchecked(low + maskLow);
            ulong carry = sumLow < low ? 1UL : 0UL;
            ulong sumHigh = unchecked(high + maskHigh + carry);
            BinaryPrimitives.WriteUInt64LittleEndian(actual, sumLow);
            BinaryPrimitives.WriteUInt64LittleEndian(actual.AsSpan(8), sumHigh);
            if (!actual.AsSpan().SequenceEqual(expected))
                throw new InvalidOperationException($"Poly1305 vector failed: {vector.GetProperty("description").GetString()}");
        }
    }

    private static void TestXChaCha()
    {
        using JsonDocument document = JsonDocument.Parse(System.IO.File.ReadAllText(
            System.IO.Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "..", "test_vectors", "XChaCha", "XChaCha12_32.json")));
        foreach (JsonElement vector in document.RootElement.EnumerateArray())
        {
            byte[] key = Convert.FromHexString(vector.GetProperty("input").GetProperty("key_hex").GetString()!);
            byte[] nonce = Convert.FromHexString(vector.GetProperty("input").GetProperty("nonce_hex").GetString()!);
            foreach (JsonElement test in vector.GetProperty("tests").EnumerateArray())
            {
                ulong offset = test.GetProperty("input").GetProperty("offset").GetUInt64();
                byte[] expected = Convert.FromHexString(test.GetProperty("result_hex").GetString()!);
                byte[] actual = new byte[64];
                XChaCha12.Crypt(key, nonce, actual, offset);
                if (!actual.AsSpan().SequenceEqual(expected))
                    throw new InvalidOperationException($"XChaCha12 vector failed at offset {offset}");
            }
        }
    }

    private static void TestAdiantum()
    {
        using JsonDocument document = JsonDocument.Parse(System.IO.File.ReadAllText(
            System.IO.Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "..", "test_vectors", "Adiantum", "Adiantum_XChaCha12_32_AES256.json")));
        foreach (JsonElement vector in document.RootElement.EnumerateArray())
        {
            byte[] key = Convert.FromHexString(vector.GetProperty("input").GetProperty("key_hex").GetString()!);
            byte[] tweak = Convert.FromHexString(vector.GetProperty("input").GetProperty("tweak_hex").GetString()!);
            byte[] plaintext = Convert.FromHexString(vector.GetProperty("plaintext_hex").GetString()!);
            byte[] expected = Convert.FromHexString(vector.GetProperty("ciphertext_hex").GetString()!);

            using DZen.Adiantum.Adiantum cipher = new(key);
            byte[] encrypted = (byte[])plaintext.Clone();
            cipher.Encrypt(encrypted, tweak);
            if (!encrypted.AsSpan().SequenceEqual(expected))
            {
                throw new InvalidOperationException(
                    $"Adiantum vector failed: length={plaintext.Length}, tweak={tweak.Length}, description={vector.GetProperty("description").GetString()}, expected={Convert.ToHexString(expected).ToLowerInvariant()}, actual={Convert.ToHexString(encrypted).ToLowerInvariant()}");
            }

            cipher.Decrypt(encrypted, tweak);
            if (!encrypted.AsSpan().SequenceEqual(plaintext))
                throw new InvalidOperationException("Adiantum round trip failed.");
        }
    }

    private static void TestLargeInputs()
    {
        byte[] key = new byte[32];
        byte[] tweak = new byte[256 * 1024];
        byte[] plaintext = new byte[1024 * 1024 + 17];
        Random random = new(0x4154);
        random.NextBytes(key);
        random.NextBytes(tweak);
        random.NextBytes(plaintext);
        byte[] data = (byte[])plaintext.Clone();
        Exception? error = null;
        System.Threading.Thread thread = new(() =>
        {
            try
            {
                using DZen.Adiantum.Adiantum cipher = new(key);
                cipher.Encrypt(data, tweak);
                cipher.Decrypt(data, tweak);
                if (!data.AsSpan().SequenceEqual(plaintext))
                    throw new InvalidOperationException("Large-input Adiantum round trip failed.");
            }
            catch (Exception ex)
            {
                error = ex;
            }
        }, 128 * 1024);
        thread.Start();
        thread.Join();
        if (error is not null)
            throw new InvalidOperationException("Large-input Adiantum test failed.", error);
    }
}
