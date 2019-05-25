using FluentAssertions;
using Newtonsoft.Json;
using System.IO;
using System.Linq;
using Xunit;
using static Chaos.NaCl.CryptoBytes;

namespace Poly1305.Test
{
    public class UnitTest1
    {
        [Theory]
        [InlineData("other.json")]
        //[InlineData("Poly1305.json")]
        public void Poly1305(string filename)
        {
            var testvects = JsonConvert.DeserializeObject<TestVector[]>(File.ReadAllText($"..\\..\\..\\{filename}"));

            foreach (var vect in testvects.Skip(2))
            {
                Poly1305 p1305 = new Poly1305(FromHexString(vect.Input.KeyHex));

                byte[] hash = p1305.ComputeHash(FromHexString(vect.Input.MessageHex));

                hash.Should().BeEquivalentTo(FromHexString(vect.MacHex));
            }
        }

        //[Fact]
        public void Test()
        {
            TestVector vect = new TestVector
            {
                Input = new Input
                {
                    KeyHex = "01020304050607080910111213141516",
                    MessageHex = "0102030405060708091011121314151617"
                }
            };

            Poly1305 p1305 = new Poly1305(FromHexString(vect.Input.KeyHex));

            byte[] hash = p1305.ComputeHash(FromHexString(vect.Input.MessageHex));

            hash.Should().BeEquivalentTo(FromHexString(vect.MacHex));
        }
    }
}

