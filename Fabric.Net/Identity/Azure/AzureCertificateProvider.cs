using System;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Fabric.Net.Extensions;
using Grpc.Core;
using Microsoft.Azure.KeyVault;
using Microsoft.Azure.KeyVault.Models;
using Microsoft.Azure.KeyVault.WebKey;

namespace Fabric.Net.Identity.Azure
{
    public class AzureCertificateProvider : ICertificateProvider
    {
        private readonly IKeyVaultClient _keyVault;
        private readonly CertificateBundle _certificateBundle;

        public AzureCertificateProvider(IKeyVaultClient keyVault, CertificateBundle certificateBundle)
        {
            _keyVault = keyVault;
            _certificateBundle = certificateBundle;
        }

        public byte[] GetCertificate()
        {
            return _certificateBundle.Cer;
        }

        public string GetCertificateHash()
        {
            using (var hasher = SHA256.Create())
            {
                return Convert.ToBase64String(hasher.ComputeHash(GetCertificate()));
            }
        }

        public async Task<byte[]> Sign(byte[] body)
        {
            using (var hasher = SHA256.Create())
            {
                var digest = hasher.ComputeHash(body);
                var result = await _keyVault.SignAsync(_certificateBundle.KeyIdentifier.Identifier, JsonWebKeySignatureAlgorithm.ES256, digest);

                return result.Result;
            }
        }

        public async Task<KeyCertificatePair> GetKeyCertificatePair()
        {
            var secret = await _keyVault.GetSecretAsync(_certificateBundle.SecretIdentifier.Identifier);
            var pem = CertificateExtensions.ParsePem(secret.Value);

            return new KeyCertificatePair(pem["CERTIFICATE"], pem["PRIVATE KEY"]);
        }
    }
}
