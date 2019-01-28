using System;
using System.IO;
using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pkcs;

namespace Fabric.Net.Certificates
{
    public static class ECKeyExtensions
    {
        //public static string ToJson(this ECDsa key)
        //{
        //    var keyParams = key.ExportParameters(true);

        //    return JsonConvert.SerializeObject(new
        //    {
        //        PublicKey = new
        //        {
        //            X = new AsnEncodedData(keyParams.Q.X).Format(true),
        //            Y = new AsnEncodedData(keyParams.Q.Y).Format(true)
        //        },
        //        PrivateKey = new AsnEncodedData(keyParams.D).Format(true)
        //    });
        //}

        //public static ECDsa FromJson(this ECDsa key, string json)
        //{
        //    var keyParams = JsonConvert.DeserializeObject<ECParameters>(json);

        //    key.ImportParameters(keyParams);

        //    return key;
        //}

        public static void ExportToPem(this AsymmetricCipherKeyPair keyPair, string keyPath)
        {
            var privateKey = PrivateKeyInfoFactory.CreatePrivateKeyInfo(keyPair.Private);
            privateKey.GetDerEncoded().ExportToPem("PRIVATE KEY", keyPath);
        }

        public static void ExportToPem(this byte[] derEncoded, string type, string keyPath)
        {
            File.WriteAllText(keyPath, derEncoded.ToPemEncoded(type));
        }

        public static string ToPemEncoded(this byte[] derEncoded, string type)
        {
            var header = $"-----BEGIN {type}-----";
            var derString = Convert.ToBase64String(derEncoded, Base64FormattingOptions.InsertLineBreaks);
            var tail = $"-----END {type}-----";

            return $"{header}\n{derString}\n{tail}\n";
        }

        public static string ToBase64(this string source)
        {
            return Convert.ToBase64String(Encoding.UTF8.GetBytes(source));
        }
    }
}
