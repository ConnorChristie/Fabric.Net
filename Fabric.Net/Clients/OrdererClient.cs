using System;
using System.Linq;
using System.Threading.Tasks;
using Common;
using Fabric.Net.Identity;
using Google.Protobuf;
using Msp;
using static Common.Policy.Types;
using static Orderer.AtomicBroadcast;

namespace Fabric.Net.Clients
{
    public class OrdererClient : GrpcClient
    {
        private readonly AtomicBroadcastClient _abClient;

        public OrdererClient(string ordererEndpoint, IIdentity identity) : base(ordererEndpoint, identity)
        {
            _abClient = new AtomicBroadcastClient(GetGrpcChannel());
        }

        public async Task CreateChannel(string name)
        {
            var writeSet = new ConfigGroup();
            writeSet.Values["Consortium"] = new ConfigValue
            {
                ModPolicy = "Admins",
                Value = new Consortium
                {
                    Name = "SampleConsortium"
                }.ToByteString()
            };
            writeSet.Groups["Application"] = new ConfigGroup();
            writeSet.Groups["Application"].Version = 1;
            writeSet.Groups["Application"].Groups["Org1MSP"] = new ConfigGroup();
            // writeSet.Groups["Application"].Groups["Org2MSP"] = new ConfigGroup();
            writeSet.Groups["Application"].ModPolicy = "Admins";
            writeSet.Groups["Application"].Policies["Admins"] = new ConfigPolicy
            {
                ModPolicy = "Admins",
                Policy = new Policy
                {
                    Type = (int)PolicyType.ImplicitMeta,
                    Value = new ImplicitMetaPolicy
                    {
                        Rule = ImplicitMetaPolicy.Types.Rule.Majority,
                        SubPolicy = "Admins"
                    }.ToByteString()
                }
            };
            writeSet.Groups["Application"].Policies["Readers"] = new ConfigPolicy
            {
                ModPolicy = "Admins",
                Policy = new Policy
                {
                    Type = (int)PolicyType.ImplicitMeta,
                    Value = new ImplicitMetaPolicy
                    {
                        SubPolicy = "Readers"
                    }.ToByteString()
                }
            };
            writeSet.Groups["Application"].Policies["Writers"] = new ConfigPolicy
            {
                ModPolicy = "Admins",
                Policy = new Policy
                {
                    Type = (int)PolicyType.ImplicitMeta,
                    Value = new ImplicitMetaPolicy
                    {
                        SubPolicy = "Writers"
                    }.ToByteString()
                }
            };

            var configUpdate = new ConfigUpdateEnvelope
            {
                ConfigUpdate = new ConfigUpdate
                {
                    ChannelId = name,
                    ReadSet = new ConfigGroup(),
                    WriteSet = writeSet
                }.ToByteString()
            };

            // TODO extract this signing part out
            // Multiple sigs to be gathered off chain??
            var sigHeader = new SignatureHeader
            {
                Nonce = ByteString.CopyFrom(GetNonce()),
                Creator = new SerializedIdentity
                {
                    Mspid = "Org1MSP",
                    IdBytes = ByteString.CopyFrom(Identity.CertificateProvider.GetCertificate())
                }.ToByteString()
            };

            var signingBytes = sigHeader.ToByteArray().Concat(configUpdate.ConfigUpdate.ToByteArray()).ToArray();
            var signature = await Identity.CertificateProvider.Sign(signingBytes);

            configUpdate.Signatures.Add(new ConfigSignature
            {
                SignatureHeader = sigHeader.ToByteString(),
                Signature = ByteString.CopyFrom(signature)
            });

            var header = new Header
            {
                ChannelHeader = new ChannelHeader
                {
                    Type = (int)HeaderType.ConfigUpdate,
                    Version = 1,
                    ChannelId = name,
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

            var payload = new Payload
            {
                Header = header,
                Data = configUpdate.ToByteString()
            };

            var payloadSignature = await Identity.CertificateProvider.Sign(payload.ToByteArray());

            await _abClient.Broadcast().RequestStream.WriteAsync(new Envelope
            {
                Payload = payload.ToByteString(),
                Signature = ByteString.CopyFrom(payloadSignature)
            });
        }
    }
}