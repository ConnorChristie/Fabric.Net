using System.Threading.Tasks;

namespace Fabric.Net.Signers
{
    public interface ISignatureProvider
    {
        byte[] GetCertificate();

        Task<byte[]> Sign(byte[] body);
    }
}
