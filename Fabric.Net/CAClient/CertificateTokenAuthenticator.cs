using System.Linq;
using System.Text;
using Fabric.Net.Extensions;
using Fabric.Net.Identity;
using Fabric.Net.Signers;
using Newtonsoft.Json;
using RestSharp;
using RestSharp.Authenticators;

namespace Fabric.Net.Fabric
{
    public class CertificateTokenAuthenticator : IAuthenticator
    {
        private readonly ICertificateProvider _signatureProvider;

        public CertificateTokenAuthenticator(ICertificateProvider signatureProvider)
        {
            _signatureProvider = signatureProvider;
        }

        public void Authenticate(IRestClient client, IRestRequest request)
        {
            var signer = new ECDsaSigner(_signatureProvider);

            var body = request.Parameters.FirstOrDefault(x => x.Type == ParameterType.RequestBody);
            var bodyContent = body != null ? JsonConvert.SerializeObject(body.Value) : "";

            var b64cert = _signatureProvider.GetCertificate().ToPemEncoded("CERTIFICATE").ToBase64();
            var b64body = bodyContent.ToBase64();

            var signBody = Encoding.UTF8.GetBytes($"{b64body}.{b64cert}");
            var signature = signer.SignData(signBody).Result;

            request.AddHeader("Authorization", $"{b64cert}.{signature}");
        }
    }
}
