using System;
using System.IO;
using System.Linq;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using Fabric.Net.Certificates;
using Fabric.Net.Fabric.Models;
using Fabric.Net.Identity;
using Fabric.Net.Signers;
using Org.BouncyCastle.OpenSsl;
using RestSharp;
using RestSharp.Authenticators;

namespace Fabric.Net
{
    public class FabricClient
    {
        private readonly IRestClient _caClient;

        public Org.BouncyCastle.X509.X509Certificate TlsCert { get; set; }

        public FabricClient()
        {
            _caClient = new RestClient("https://ica-org0:7054")
            {
                RemoteCertificateValidationCallback = HandleRemoteCertificateValidationCallback
            };
        }

        public void LoadTlsCert(string path)
        {
            var pem = new PemReader(File.OpenText(path));
            TlsCert = (Org.BouncyCastle.X509.X509Certificate)pem.ReadObject();
        }

        public async Task Enroll(User user, string certName, string enrollmentSecret)
        {
            var request = new RestRequest("api/v1/enroll");
            request.AddJsonBody(new
            {
                certificate_request = await user.CreateSigningRequest(certName)
            });

            var auth = new HttpBasicAuthenticator(certName, enrollmentSecret);
            auth.Authenticate(_caClient, request);

            var response = await _caClient.PostAsync<EnrollmentResponse>(request);
            var cert = new X509Certificate2(Convert.FromBase64String(response.result.Cert));

            await user.MergeSignedCertificate(certName, cert);
        }

        public async Task GetIdentities(ISignatureProvider signatureProvider)
        {
            var signer = new ECDsaSigner(signatureProvider);

            var body = "";
            var b64cert = signatureProvider.GetCertificate().ToPemEncoded("CERTIFICATE").ToBase64();
            var b64body = body.ToBase64();

            var signBody = Encoding.UTF8.GetBytes($"{b64body}.{b64cert}");
            var signature = await signer.SignData(signBody);

            var request = new RestRequest("api/v1/identities");
            request.AddHeader("Authorization", $"{b64cert}.{signature}");

            var response = await _caClient.GetAsync<object>(request);

        }

        private bool HandleRemoteCertificateValidationCallback(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            if (sslPolicyErrors == SslPolicyErrors.None)
            {
                return true;
            }

            using (var hasher = SHA256.Create())
            {
                var trustedHash = hasher.ComputeHash(TlsCert.GetEncoded());
                var thisHashed = certificate.GetCertHash(HashAlgorithmName.SHA256);

                return trustedHash.SequenceEqual(thisHashed);
            }
        }
    }
}
