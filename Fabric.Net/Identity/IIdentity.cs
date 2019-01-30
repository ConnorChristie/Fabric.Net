using Fabric.Net.Signers;

namespace Fabric.Net.Identity
{
    public interface IIdentity
    {
        ICertificateProvider CertificateProvider { get; }
    }
}
