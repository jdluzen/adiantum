using Newtonsoft.Json;

namespace NH.Test
{
    public class Cipher
    {
        [JsonProperty("cipher")]
        public string CipherType { get; set; }
        public int Passes { get; set; }
        [JsonProperty("word_bytes")]
        public int WordBytes { get; set; }
        public int Stride { get; set; }
        public int Unitcount { get; set; }
    }

    public class Input
    {
        [JsonProperty("key_hex")]
        public string KeyHex { get; set; }
        [JsonProperty("message_hex")]
        public string MessageHex { get; set; }
    }

    public class TestVector
    {
        public Cipher Cipher { get; set; }
        public string Description { get; set; }
        public Input Input { get; set; }
        [JsonProperty("hash_hex")]
        public string HashHex { get; set; }
    }
}
