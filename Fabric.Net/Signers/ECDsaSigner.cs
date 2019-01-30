using System;
using System.IO;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Fabric.Net.Identity;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Math;

namespace Fabric.Net.Signers
{
    public class ECDsaSigner
    {
        private readonly ICertificateProvider _signatureProvider;

        public ECDsaSigner(ICertificateProvider signatureProvider)
        {
            _signatureProvider = signatureProvider;
        }

        /// <summary>
        /// Signs the specified data and returns an Asn.1 encoded ECDsa signature
        /// </summary>
        /// <returns>Asn.1 encoded ECDsa signature</returns>
        /// <param name="data">The data to sign</param>
        public async Task<string> SignData(byte[] data)
        {
            var response = await _signatureProvider.Sign(data);

            var r = new byte[32];
            var s = new byte[32];
            Array.Copy(response, 0, r, 0, 32);
            Array.Copy(response, 32, s, 0, 32);

            using (var bOut = new MemoryStream())
            {
                using (var encoder = new Asn1OutputStream(bOut))
                {
                    encoder.WriteObject(new DerSequence(
                        new DerInteger(new BigInteger(1, r)),
                        new DerInteger(new BigInteger(1, s))
                    ));

                    return Convert.ToBase64String(bOut.ToArray());
                }
            }
        }
    }
}
