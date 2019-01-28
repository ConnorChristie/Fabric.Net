using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Fabric.Net.Certificates;
using Fabric.Net.Signers;
using Microsoft.Azure.KeyVault;
using Microsoft.Azure.KeyVault.Models;
using Microsoft.Azure.KeyVault.WebKey;
using Microsoft.Azure.Services.AppAuthentication;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Math;

namespace Fabric.Net.Identity
{
    public class User
    {
        private static readonly IKeyVaultClient _keyVault = new KeyVaultClient(new KeyVaultClient.AuthenticationCallback(new AzureServiceTokenProvider().KeyVaultTokenCallback));
        private readonly string _vaultUrl = "https://fabcon-certs.vault.azure.net/";

        //public string Name { get; set; }

        //public ECDsa KeyPair { get; set; }
        //public X509Certificate2 Certificate { get; set; }

        public ISignatureProvider SignatureProvider { get; }

        public CertificateBundle CertificateBundle { get; set; }
        //public CertificateRequest CertificateRequest { get; set; }

        public User(ISignatureProvider signatureProvider)
        {
            SignatureProvider = signatureProvider;
        }

        //private static readonly ECCurve _ecCurve = ECCurve.NamedCurves.nistP256;
        //private static readonly HashAlgorithmName _hashAlgorithm = HashAlgorithmName.SHA256;

        //public User SetCertificate(string certificatePath)
        //{
        //    var content = File.ReadAllText(certificatePath);

        //    Certificate = new X509Certificate2(Encoding.UTF8.GetBytes(content));

        //    return this;
        //}

        //public User SetKeyPair(string keyPath)
        //{
        //    var content = File.ReadAllText(keyPath);

        //    KeyPair = ECDsa.Create().FromJson(content);

        //    return this;
        //}

        //public static User NewUser(string name)
        //{
        //    var subjectName = $"CN={name}";
        //    var key = ECDsa.Create();

        //    key.GenerateKey(_ecCurve);

        //    return new User
        //    {
        //        Name = name,
        //        KeyPair = key,
        //        CertificateRequest = new CertificateRequest(subjectName, key, _hashAlgorithm)
        //    };
        //}

        //public string CreateSigningRequest()
        //{
        //    return CertificateRequest.CreateSigningRequest().ToPemEncoded("CERTIFICATE REQUEST");
        //}

        //var generator = new ECKeyPairGenerator("ECDSA");
        //generator.Init(new ECKeyGenerationParameters(SecObjectIdentifiers.SecP256r1, new SecureRandom()));

        //var keyPair = generator.GenerateKeyPair();
        //keyPair.ExportToPem("/Users/connor/Documents/git/Fabric.Net/Fabric.Net/certs/connor-mac2/private.pem");

        //var certName = new X509Name("CN=connor234");
        //var certificationRequest = new Pkcs10CertificationRequestDelaySigned("SHA256withECDSA", certName, keyPair.Public, null);

        //certificationRequest.GetDerEncoded().ExportToPem("CERTIFICATE REQUEST", "/Users/connor/Documents/git/Fabric.Net/Fabric.Net/certs/connor-mac2/csr.pem");

        public async Task<CertificateOperation> NewAzureCertificate(string certName)
        {
            var policy = new CertificatePolicy
            {
                X509CertificateProperties = new X509CertificateProperties
                {
                    Subject = $"CN={certName}",
                    Ekus = new List<string> { "1.3.6.1.5.5.7.3.1", "1.3.6.1.5.5.7.3.2" },
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
                    Curve = "P-256"
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

        public static async Task<User> FromAzure(IKeyVaultClient keyVault, string certificateIdentifier)
        {
            var certBundle = await keyVault.GetCertificateAsync(certificateIdentifier);
            var signatureProvider = new AzureSignatureProvider(keyVault, certBundle);

            return new User(signatureProvider);
        }
    }
}
