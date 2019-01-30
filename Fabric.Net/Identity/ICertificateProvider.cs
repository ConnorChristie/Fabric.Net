using System.Threading.Tasks;
using Grpc.Core;

namespace Fabric.Net.Identity
{
    public interface ICertificateProvider
    {
        byte[] GetCertificate();

        string GetCertificateHash();

        Task<byte[]> Sign(byte[] body);

        Task<KeyCertificatePair> GetKeyCertificatePair();
    }
}
