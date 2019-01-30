using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Fabric.Net.Extensions;
using Microsoft.Azure.KeyVault;
using Microsoft.Azure.KeyVault.Models;
using Microsoft.Azure.Services.AppAuthentication;

namespace Fabric.Net.Identity.Azure
{
    public class AzureIdentity : IIdentity
    {
        private static readonly IKeyVaultClient _keyVault = new KeyVaultClient(new KeyVaultClient.AuthenticationCallback(new AzureServiceTokenProvider().KeyVaultTokenCallback));
        private readonly string _vaultUrl = "https://fabcon-certs.vault.azure.net/";

        public ICertificateProvider CertificateProvider { get; }
        public CertificateBundle CertificateBundle { get; set; }

        public AzureIdentity(ICertificateProvider signatureProvider)
        {
            CertificateProvider = signatureProvider;
        }

        public static async Task<AzureIdentity> FromKeyVault(IKeyVaultClient keyVault, string certificateIdentifier)
        {
            var certBundle = await keyVault.GetCertificateAsync(certificateIdentifier);
            var signatureProvider = new AzureCertificateProvider(keyVault, certBundle);

            return new AzureIdentity(signatureProvider);
        }

        public async Task<string> CreateSigningRequest(string certName)
        {
            var cert = await NewAzureCertificate(certName);
            return cert.Csr.ToPemEncoded("CERTIFICATE REQUEST");
        }

        public async Task MergeSignedCertificate(string certName, X509Certificate2 certificate)
        {
            CertificateBundle = await _keyVault.MergeCertificateAsync(_vaultUrl, certName, new X509Certificate2Collection
            {
                certificate
            });
        }

        private async Task<CertificateOperation> NewAzureCertificate(string certName)
        {
            var policy = new CertificatePolicy
            {
                X509CertificateProperties = new X509CertificateProperties
                {
                    Subject = $"CN={certName}",
                    Ekus = new List<string>
                    // Taken from Azure Key Vault creation page
                    {
                        "1.3.6.1.5.5.7.3.1", // id-kp-serverAuth
                        "1.3.6.1.5.5.7.3.2"  // id-kp-clientAuth
                    },
                    KeyUsage = new List<string>
                    {
                        KeyUsageType.DigitalSignature,
                        KeyUsageType.KeyEncipherment
                    }
                },
                KeyProperties = new KeyProperties
                {
                    KeySize = 256,
                    KeyType = "EC",
                    Curve = "P-256",
                    Exportable = true
                },
                IssuerParameters = new IssuerParameters
                {
                    Name = "Unknown" // External CA
                },
                SecretProperties = new SecretProperties
                {
                    ContentType = CertificateContentType.Pem
                }
            };

            return await _keyVault.CreateCertificateAsync(_vaultUrl, certName, policy);
        }
    }
}
