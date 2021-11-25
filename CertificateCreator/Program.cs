using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;
using System.Security.Cryptography.X509Certificates;

namespace CertificateCreator
{
    class Program
    {
        internal static void CreateCertificate(string savePath, string commonName, string password)
        {
            if (!commonName.StartsWith("CN=", StringComparison.OrdinalIgnoreCase))
                commonName = "CN=" + commonName;

            byte[] certificateData = Certificate.CreateSelfSignCertificatePfx(commonName, //host name
                DateTime.Now, //not valid before
                DateTime.Now.AddYears(5), //not valid after
                password);

            using (BinaryWriter binWriter = new BinaryWriter(File.Open(savePath, FileMode.Create)))
            {
                binWriter.Write(certificateData);
                binWriter.Flush();

                // Create a collection object and populate it using the PFX file
                X509Certificate2Collection collection = new X509Certificate2Collection();
                collection.Import(certificateData, password, X509KeyStorageFlags.PersistKeySet);

                foreach (X509Certificate2 cert in collection)
                {
                    Console.WriteLine("Subject is: '{0}'", cert.Subject);
                    Console.WriteLine("Issuer is:  '{0}'", cert.Issuer);

                    // Import the certificate into an X509Store object
                    var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
                    store.Open(OpenFlags.ReadWrite);
                    if (!store.Certificates.Contains(cert))
                    {
                        store.Add(cert);
                    }
                    store.Close();
                }
            }
        }

        static void Main(string[] args)
        {
            Console.WriteLine("Please enter Common Name:");
            var commonName = Console.ReadLine();
            Console.WriteLine("Please enter Password:");
            var password = Console.ReadLine();
            Console.WriteLine("Please enter Save Path:");
            var savePath = Console.ReadLine();

            CreateCertificate(savePath, commonName, password);
            Console.WriteLine("CreateCertificate successfull, press any key to quit!");
            Console.ReadKey();
        }
    }
}
