using Fabric.Net.Identity;

namespace Fabric.Net.Clients
{
    public abstract class BaseClient
    {
        public string Endpoint { get; set; }

        public IIdentity Identity { get; set; }

        public BaseClient(string endpoint, IIdentity identity)
        {
            Endpoint = endpoint;
            Identity = identity;
        }
    }
}
