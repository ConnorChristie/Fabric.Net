using System;
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;
using Common;
using Fabric.Net.Identity;
using Google.Protobuf;
using Google.Protobuf.Collections;
using Msp;
using Org.BouncyCastle.Security;
using Protos;
using static Discovery.Discovery;
using static Protos.Endorser;

namespace Fabric.Net.Clients
{
    public class PeerClient : GrpcClient
    {
        private readonly EndorserClient _endorserClient;
        private readonly DiscoveryClient _discoveryClient;

        public PeerClient(string peerEndpoint, IIdentity identity) : base(peerEndpoint, identity)
        {
            var channel = GetGrpcSecureChannel().Result;

            _endorserClient = new EndorserClient(channel);
            _discoveryClient = new DiscoveryClient(channel);
        }

        public async Task GenerateUnsignedProposal()
        {
            var header = new Header
            {
                ChannelHeader = new ChannelHeader
                {
                    Type = (int)HeaderType.EndorserTransaction,
                    Version = 1,
                    ChannelId = "mychannel",
                    TxId = Guid.NewGuid().ToString(),
                    Timestamp = Google.Protobuf.WellKnownTypes.Timestamp.FromDateTime(DateTime.UtcNow),
                    TlsCertHash = ByteString.FromBase64(Identity.CertificateProvider.GetCertificateHash())
                }.ToByteString(),

                SignatureHeader = new SignatureHeader
                {
                    Nonce = ByteString.CopyFrom(GetNonce()),
                    Creator = new SerializedIdentity
                    {
                        Mspid = "Org1MSP",
                        IdBytes = ByteString.CopyFrom(Identity.CertificateProvider.GetCertificate())
                    }.ToByteString()
                }.ToByteString()
            };

            var input = new ChaincodeInput();
            input.Args.Add(ByteString.CopyFromUtf8("hello"));

            var proposal = new Proposal
            {
                Header = header.ToByteString(),
                Payload = new ChaincodeProposalPayload
                {
                    Input = new ChaincodeInvocationSpec
                    {
                        ChaincodeSpec = new ChaincodeSpec
                        {
                            Type = ChaincodeSpec.Types.Type.Golang,
                            ChaincodeId = new ChaincodeID
                            {
                                Path = "/hello",
                                Name = "MyCC",
                                Version = "1.0"
                            },
                            Input = input
                        }
                    }.ToByteString()
                }.ToByteString()
            };

            var proposalBytes = proposal.ToByteArray();
            var signedProposal = await Identity.CertificateProvider.Sign(proposalBytes);

            var response = await _endorserClient.ProcessProposalAsync(new SignedProposal
            {
                Signature = ByteString.CopyFrom(signedProposal),
                ProposalBytes = ByteString.CopyFrom(proposalBytes)
            });
        }
    }
}
