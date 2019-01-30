using System;
using System.Diagnostics;
using System.IO;
using System.Threading.Tasks;
using Fabric.Net.CAClient;
using Fabric.Net.Clients;
using Fabric.Net.Extensions;
using Fabric.Net.Fabric;
using Fabric.Net.Identity;
using Fabric.Net.Identity.Azure;
using Grpc.Core;
using Microsoft.Azure.KeyVault;
using Microsoft.Azure.Services.AppAuthentication;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using static Protos.Endorser;

namespace Fabric.Net.Tests
{
    [TestClass]
    public class UnitTest1
    {
        [TestMethod]
        public async Task TestMethod1()
        {
            try
            {
                //await Class1.Hehe();

                var keyVault = new KeyVaultClient(new KeyVaultClient.AuthenticationCallback(new AzureServiceTokenProvider().KeyVaultTokenCallback));
                var client = new FabricCaClient("https://ica-org0:7054", CertificateExtensions.LoadCertificate("/Users/connor/Documents/git/Fabric.Net/Fabric.Net/Certs/peer1-ca-chain.pem"));

                //await client.Enroll(new User(), "connor-mac-5", "pcsgYPGbPKqT");

                var user = await AzureIdentity.FromKeyVault(keyVault, "https://fabcon-certs.vault.azure.net/certificates/connor-mac-5/94e6b940982e48f2833fc0085c0a1006");
                
                var ordererClient = new OrdererClient("orderer1-org0:7050", user);
                await ordererClient.CreateChannel("mychannel");
                
                // var peerClient = new PeerClient("peer1-org0:7051", user);
                // await peerClient.GenerateUnsignedProposal();



                //var channel = await peerClient.OpenGrpcChannel();

                //var peer = new EndorserClient(channel);
                //var response = await peer.ProcessProposalAsync(new Protos.SignedProposal());

                //await client.GetIdentities(user.SignatureProvider);
            } catch (Exception e)
            {
                Debug.WriteLine(e);

                throw e;
            }
        }

        //[TestMethod]
        //public void TestPemReader()
        //{
        //    var pem = CertificateExtensions.ParsePem(File.ReadAllText("/Users/connor/Documents/git/Fabric.Net/Fabric.Net/certs/connor-mac-5.priv"));
        //    var keyCertPair = new KeyCertificatePair(pem["CERTIFICATE"], pem["PRIVATE KEY"]);
        //}
    }
}
