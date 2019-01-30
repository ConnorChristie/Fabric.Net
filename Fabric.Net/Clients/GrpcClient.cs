using System.IO;
using System.Text;
using System.Threading.Tasks;
using Fabric.Net.Fabric;
using Fabric.Net.Identity;
using Grpc.Core;
using Org.BouncyCastle.Security;

namespace Fabric.Net.Clients
{
    public abstract class GrpcClient : BaseClient
    {
        private readonly SecureRandom _random = new SecureRandom();

        public GrpcClient(string endpoint, IIdentity identity) : base(endpoint, identity)
        {
        }

        public Channel GetGrpcChannel()
        {
            return new Channel(Endpoint, ChannelCredentials.Insecure);
        }

        public async Task<Channel> GetGrpcSecureChannel()
        {
            // ca-chain = peer ca cert + ca chain
            var caChainCert = Encoding.UTF8.GetString(await File.ReadAllBytesAsync("/Users/connor/Documents/git/Fabric.Net/Fabric.Net/Certs/peer1-ca-chain.pem"));

            var clientCert = await Identity.CertificateProvider.GetKeyCertificatePair();
            var channelCreds = new SslCredentials(caChainCert, clientCert);

            return new Channel(Endpoint, channelCreds);
        }

        protected byte[] GetNonce()
        {
            var nonce = new byte[24];
            _random.NextBytes(nonce);

            return nonce;
        }
    }
}
