using Newtonsoft.Json;

namespace Poly1305.Test
{
    public class Lengths
    {
        public int Key { get; set; }
        public int Mask { get; set; }
        public int Output { get; set; }
    }

    public class Cipher
    {
        [JsonProperty("cipher")]
        public string CipherType { get; set; }
        public Lengths Lengths { get; set; }
    }

    public class Input
    {
        [JsonProperty("key_hex")]
        public string KeyHex { get; set; }
        [JsonProperty("mask_hex")]
        public string MaskHex { get; set; }
        [JsonProperty("message_hex")]
        public string MessageHex { get; set; }
    }

    public class TestVector
    {
        public Cipher Cipher { get; set; }
        public string Description { get; set; }
        public Input Input { get; set; }
        [JsonProperty("mac_hex")]
        public string MacHex { get; set; }
    }
}
