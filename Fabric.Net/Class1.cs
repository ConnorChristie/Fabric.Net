using System;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Threading.Tasks;
using Grpc.Core;
using static Protos.Endorser;

namespace Fabric.Net
{
    public class Class1
    {
        public static async Task Hehe()
        {
            var cert = File.ReadAllText("/Users/connor/Documents/git/Fabric.Net/Fabric.Net/Certs/peer1-ca-chain.pem");
            var pub = File.ReadAllText("/Users/connor/Documents/git/Fabric.Net/Fabric.Net/Certs/connor-mac-5.pub");
            var priv = File.ReadAllText("/Users/connor/Documents/git/Fabric.Net/Fabric.Net/Certs/connor-mac-5.priv");

            var channelCreds = new SslCredentials(cert, new KeyCertificatePair(pub, priv));
            var channel = new Channel("peer1-org0", 7051, channelCreds);

            var peer = new EndorserClient(channel);
            var response = await peer.ProcessProposalAsync(new Protos.SignedProposal());

            Debug.WriteLine(response.Version);

            await channel.ShutdownAsync();
        }

        public static void Main(string[] args)
        {
            Hehe().Wait();
        }
    }
}
