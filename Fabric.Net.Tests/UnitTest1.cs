using System;
using System.Diagnostics;
using System.Threading.Tasks;
using Fabric.Net.Identity;
using Microsoft.Azure.KeyVault;
using Microsoft.Azure.Services.AppAuthentication;
using Microsoft.VisualStudio.TestTools.UnitTesting;

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
                var keyVault = new KeyVaultClient(new KeyVaultClient.AuthenticationCallback(new AzureServiceTokenProvider().KeyVaultTokenCallback));

                var client = new FabricClient();
                client.LoadTlsCert("/Users/connor/Documents/git/Fabric.Net/Fabric.Net/certs/ica-org0-ca-tls.pem");

                //await client.Enroll(new User(), "connor-mac-5", "pcsgYPGbPKqT");

                var user = await User.FromAzure(keyVault, "https://fabcon-certs.vault.azure.net/certificates/connor-mac-5/94e6b940982e48f2833fc0085c0a1006");
                await client.GetIdentities(user.SignatureProvider);
            } catch (Exception e)
            {
                Debugger.Break();
            }
        }
    }
}
