using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.Security;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.X509;
using RestSharp;
using RestSharp.Authenticators;

namespace Fabric.Net
{
    public class Class1
    {
        public static async Task Hehe()
        {
            var key = ECDsa.Create();
            key.GenerateKey(ECCurve.NamedCurves.nistP256);

            var csr = new System.Security.Cryptography.X509Certificates.CertificateRequest("CN=connor-mac2", key, HashAlgorithmName.SHA256);

            var pk = PemEncode(csr.PublicKey.EncodedKeyValue.RawData);
            File.WriteAllText("/Users/connor/Documents/git/Fabric.Net/Fabric.Net/certs/connor-mac2/public.pem", pk);


            var pem = new PemReader(File.OpenText("/Users/connor/Documents/git/Fabric.Net/Fabric.Net/certs/ica-org0-ca-tls.pem"));
            var cert = (X509Certificate)pem.ReadObject();


            var client = new RestClient("https://10.53.0.8:7054");
            client.Authenticator = new HttpBasicAuthenticator("connor-mac2", "xYpJmomAdWxG");
            client.RemoteCertificateValidationCallback = (sender, certificate, chain, sslPolicyErrors) =>
            {
                if (sslPolicyErrors == SslPolicyErrors.None)
                {
                    return true;
                }

                using (var hasher = SHA256.Create())
                {
                    var trustedHash = hasher.ComputeHash(cert.GetEncoded());
                    var thisHashed = certificate.GetCertHash(HashAlgorithmName.SHA256);

                    return trustedHash.SequenceEqual(thisHashed);
                }
            };

            var request = new RestRequest("api/v1/enroll");
            request.AddJsonBody(new
            {
                certificate_request = PemEncodeSigningRequest(csr)
            });

            var response = await client.PostAsync<EnrollResponse>(request);

            var certStr = Encoding.UTF8.GetString(Convert.FromBase64String(response.result.Cert));
            File.WriteAllText("/Users/connor/Documents/git/Fabric.Net/Fabric.Net/certs/connor-mac2/cert.pem", certStr);

            //var registerBody = new
            //{
            //    id = "connor",
            //    type = "client",
            //    secret = "C0ncurr3ncy!",
            //    affiliation = "org0.department1",
            //    attrs = new[]
            //    {
            //        new
            //        {
            //            name = "admin",
            //            value = "true",
            //            ecert = true
            //        }
            //    }
            //};

            //var enrollmentCert = response.result.Cert;
            //var signed = key.SignData(Encoding.UTF8.GetBytes($"{JsonConvert.SerializeObject(registerBody)}.{enrollmentCert}"), HashAlgorithmName.SHA256);

            //// Get enrollment cert from response (enrollment.getCert().getBytes(StandardCharsets.UTF_8))
            //// Sign body . base64(cert) with private key
            //// Auth = cert . base64(signature)

            //var auth = $"{enrollmentCert}.{Convert.ToBase64String(signed)}";

            //var registerRequest = new RestRequest("api/v1/register");
            //registerRequest.AddJsonBody(registerBody);
            //registerRequest.AddHeader("Authorization", auth);

            //var registerResponse = await client.PostAsync<object>(registerRequest);

            Debugger.Break();
        }

        public static string PemEncodeSigningRequest(System.Security.Cryptography.X509Certificates.CertificateRequest request)
        {
            return PemEncode(request.CreateSigningRequest());
        }

        public static string PemEncode(byte[] bytes)
        {
            var base64Cert = Convert.ToBase64String(bytes);

            return $"-----BEGIN CERTIFICATE REQUEST-----\n{base64Cert}\n-----END CERTIFICATE REQUEST-----\n";
        }
    }

    public class EnrollResponse
    {
        public Result result { get; set; }

        public class Result
        {
            public string Cert { get; set; }
        }
    }
}
