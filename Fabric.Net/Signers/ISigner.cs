using System.Threading.Tasks;

namespace Fabric.Net.Signers
{
    public interface ISigner
    {
        Task<string> SignData(byte[] data);
    }
}
