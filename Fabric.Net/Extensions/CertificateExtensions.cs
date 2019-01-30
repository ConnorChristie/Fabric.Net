using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Utilities.IO.Pem;
using Org.BouncyCastle.X509;

namespace Fabric.Net.Extensions
{
    public static class CertificateExtensions
    {
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

        public static X509Certificate LoadCertificate(string path)
        {
            var pem = new Org.BouncyCastle.OpenSsl.PemReader(File.OpenText(path));
            return (X509Certificate)pem.ReadObject();
        }

        public static IDictionary<string, string> ParsePem(string pemContents)
        {
            var stream = new MemoryStream(Encoding.UTF8.GetBytes(pemContents));
            var pemReader = new Org.BouncyCastle.OpenSsl.PemReader(new StreamReader(stream));

            var result = new Dictionary<string, string>();

            PemObject obj;
            while ((obj = pemReader.ReadPemObject()) != null)
            {
                result[obj.Type] = obj.Content.ToPemEncoded(obj.Type);
            }

            return result;
        }
    }
}
