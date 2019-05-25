using FluentAssertions;
using Newtonsoft.Json;
using System.IO;
using Xunit;
using static Chaos.NaCl.CryptoBytes;

namespace NH.Test
{
    public class UnitTest1
    {
        [Theory]
        [InlineData("NH.json")]
        [InlineData("NH ours.json")]
        public void NH(string filename)
        {
            var testvects = JsonConvert.DeserializeObject<TestVector[]>(File.ReadAllText($"..\\..\\..\\{filename}"));

            foreach (var vect in testvects)
            {
                Nh nh = new Nh(FromHexString(vect.Input.KeyHex));
                byte[] hash = nh.ComputeHash(FromHexString(vect.Input.MessageHex));

                hash.Should().BeEquivalentTo(FromHexString(vect.HashHex));
            }
        }
    }
}
