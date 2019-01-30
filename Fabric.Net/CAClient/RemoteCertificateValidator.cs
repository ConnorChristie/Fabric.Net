using System.Linq;
using System.Net.Security;
using System.Security.Cryptography;
using Org.BouncyCastle.X509;

namespace Fabric.Net.CAClient
{
    public static class RemoteCertificateValidator
    {
        public static RemoteCertificateValidationCallback HandleRemoteCertificateValidationCallback(X509Certificate caChain)
        {
            return (sender, certificate, chain, sslPolicyErrors) =>
            {
                if (sslPolicyErrors == SslPolicyErrors.None)
                {
                    return true;
                }

                using (var hasher = SHA256.Create())
                {
                    var trustedHash = hasher.ComputeHash(caChain.GetEncoded());
                    var thisHashed = certificate.GetCertHash(HashAlgorithmName.SHA256);

                    return trustedHash.SequenceEqual(thisHashed);
                }
            };
        }
    }
}