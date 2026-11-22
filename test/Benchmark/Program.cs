using DZen.Adiantum;
using DZen.Adiantum.Internal;
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics.X86;

namespace Benchmark;

internal static class Program
{
    private delegate void NhHash(ReadOnlySpan<byte> key, ReadOnlySpan<byte> message, Span<byte> output);

    private static void Main()
    {
        Console.WriteLine($"NH/Adiantum microbenchmark; architecture={RuntimeInformation.ProcessArchitecture}; " +
                          $"SSE2={Sse2.IsSupported}, AVX2={Avx2.IsSupported}, AVX-512F={Avx512F.IsSupported}");
        Console.WriteLine("Console output only; warm-up plus median of three 150 ms samples. Timings are machine/load dependent.");

        byte[] key = new byte[Nh.KeyBytes];
        byte[] message = new byte[Nh.MessageBytes];
        byte[] output = new byte[Nh.HashBytes];
        Random random = new(0x4E48);
        random.NextBytes(key);
        random.NextBytes(message);

        int[] nhLengths = { 16, 32, 64, 128, 256, 512, 1024 };
        foreach (int length in nhLengths)
        {
            Console.WriteLine($"NH {length,4} B");
            MeasureHash("Scalar", Nh.HashScalar, key, message, output, length);
            if (Sse2.IsSupported)
                MeasureHash("SSE2", Nh.HashSse2, key, message, output, length);
            if (Avx2.IsSupported)
                MeasureHash("AVX2", Nh.HashAvx2, key, message, output, length);
            if (Avx512F.IsSupported)
                MeasureHash("AVX-512F", Nh.HashAvx512, key, message, output, length);
        }

        foreach (int length in new[] { 512, 4096, 16384 })
        {
            byte[] data = new byte[length];
            byte[] tweak = new byte[16];
            random.NextBytes(data);
            using Adiantum cipher = new(key.AsSpan(0, Adiantum.KeySize));
            double pairedNs = MeasureNanoseconds(() =>
            {
                cipher.Encrypt(data, tweak);
                cipher.Decrypt(data, tweak);
            });
            Console.WriteLine($"Adiantum {length,5} B: {pairedNs / 2:F1} ns/encrypt-or-decrypt (paired)");
        }
    }

    private static void MeasureHash(
        string name,
        NhHash hash,
        byte[] key,
        byte[] message,
        byte[] output,
        int length)
    {
        double ns = MeasureNanoseconds(() => hash(key, message.AsSpan(0, length), output));
        Console.WriteLine($"  {name,-8} {ns,9:F1} ns/op");
        GC.KeepAlive(output);
    }

    private static double MeasureNanoseconds(Action action)
    {
        for (int i = 0; i < 256; i++)
            action();

        const int batchSize = 128;
        double[] samples = new double[3];
        for (int sample = 0; sample < samples.Length; sample++)
        {
            Stopwatch stopwatch = Stopwatch.StartNew();
            long iterations = 0;
            while (stopwatch.ElapsedMilliseconds < 150)
            {
                for (int i = 0; i < batchSize; i++)
                    action();
                iterations += batchSize;
            }
            samples[sample] = stopwatch.Elapsed.TotalNanoseconds / iterations;
        }

        Array.Sort(samples);
        return samples[samples.Length / 2];
    }
}
