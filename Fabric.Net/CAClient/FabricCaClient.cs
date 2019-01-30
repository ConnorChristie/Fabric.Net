using System;
using System.IO;
using System.Linq;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Fabric.Net.Fabric;
using Fabric.Net.Identity;
using Fabric.Net.Identity.Azure;
using Fabric.Net.Models;
using Fabric.Net.Signers;
using RestSharp;
using RestSharp.Authenticators;

namespace Fabric.Net.CAClient
{
    public class FabricCaClient
    {
        private readonly IRestClient _caClient;

        public FabricCaClient(string clientEndpoint, Org.BouncyCastle.X509.X509Certificate caRootCertificate)
        {
            _caClient = new RestClient(clientEndpoint)
            {
                RemoteCertificateValidationCallback = RemoteCertificateValidator.HandleRemoteCertificateValidationCallback(caRootCertificate)
            };
        }

        public async Task Enroll(AzureIdentity user, string certName, string enrollmentSecret)
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

        public async Task GetIdentities(ICertificateProvider signatureProvider)
        {
            var request = new RestRequest("api/v1/identities");
            var auth = new CertificateTokenAuthenticator(signatureProvider);
            auth.Authenticate(_caClient, request);

            var response = await _caClient.GetAsync<object>(request);
        }
    }
}