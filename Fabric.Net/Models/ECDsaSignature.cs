using Org.BouncyCastle.Math;

namespace Fabric.Net.Models
{
    public class ECDsaSignature
    {
        public byte[] R { get; set; }
        public byte[] S { get; set; }
    }
}
