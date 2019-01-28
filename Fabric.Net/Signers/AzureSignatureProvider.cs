using System.Threading.Tasks;
using Microsoft.Azure.KeyVault;
using Microsoft.Azure.KeyVault.Models;
using Microsoft.Azure.KeyVault.WebKey;

namespace Fabric.Net.Signers
{
    public class AzureSignatureProvider : ISignatureProvider
    {
        private readonly IKeyVaultClient _keyVault;
        private readonly CertificateBundle _certificateBundle;

        public AzureSignatureProvider(IKeyVaultClient keyVault, CertificateBundle certificateBundle)
        {
            _keyVault = keyVault;
            _certificateBundle = certificateBundle;
        }

        public byte[] GetCertificate()
        {
            return _certificateBundle.Cer;
        }

        public async Task<byte[]> Sign(byte[] digest)
        {
            var result = await _keyVault.SignAsync(_certificateBundle.KeyIdentifier.Identifier, JsonWebKeySignatureAlgorithm.ES256, digest);

            return result.Result;
        }
    }
}
