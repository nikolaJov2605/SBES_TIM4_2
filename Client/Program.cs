using CertHelper;
using Manage;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.ServiceModel;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Client
{
    class Program
    {
        static void Main(string[] args)
        {
            byte[] sessionKey;
            string serviceCert = "Manager";

            NetTcpBinding binding = new NetTcpBinding();
            string address = "net.tcp://localhost:8888/WCFService";

            //Windows autetifikacija vezbe 1 /2 
            binding.Security.Mode = SecurityMode.Transport;
            binding.Security.Transport.ClientCredentialType = TcpClientCredentialType.Windows;
            binding.Security.Transport.ProtectionLevel = System.Net.Security.ProtectionLevel.EncryptAndSign;

            using (MakeClient proxy = new MakeClient(binding, new EndpointAddress(new Uri(address))))
            {
                Console.WriteLine(WindowsIdentity.GetCurrent().Name);
                sessionKey = SessionKeyHelper.CreateSessionKey();

                //pronaci u trusted people serverski sertifikat
                X509Certificate2 certificate = CertManager.GetCertificateFromStorage(StoreName.TrustedPeople, StoreLocation.LocalMachine, serviceCert);

                byte[] encryptedSessionKey = SessionKeyHelper.EncryptSessionKey(certificate, sessionKey);

                bool connected = proxy.Connect(encryptedSessionKey);

                SessionKeyHelper.PrintSessionKey(sessionKey);

                if (connected)
                {
                    while (true)
                    {
                        Console.WriteLine("Input name of mashine [type exit to exit]: ");
                        string machineStr = Console.ReadLine();

                        if (machineStr.ToLower() == "exit")
                            break;

                        Console.WriteLine("Input protocol: ");
                        string proptocol = Console.ReadLine();

                        Console.WriteLine("Input port ");
                        string ports = Console.ReadLine();
                        byte[] encryptedData = AES_CBC.EncryptData(string.Format("{0},{1},{2}", machineStr, proptocol, ports), sessionKey);
                        Console.WriteLine(Encoding.ASCII.GetString(encryptedData));
                        bool isStarted = proxy.StartNewService(encryptedData);
                        if(isStarted)
                            Console.WriteLine("Service is successfully started.");
                        else
                            Console.WriteLine("Service is not started due to blacklist configuration.");
                        Thread.Sleep(5000);
                    }

                    /*
                    encryptedData = AES_CBC.EncryptData("MortalKombat,UDP", sessionKey);
                    Console.WriteLine(Encoding.ASCII.GetString(encryptedData));
                    proxy.StartNewService(encryptedData);
                    */

                    /*
                    for (int i = 1; i < 5; i++)
                    {
                        encryptedData = AES_CBC.EncryptData("MortalKombat,UDP," + i, sessionKey);
                        Console.WriteLine(Encoding.ASCII.GetString(encryptedData));
                        proxy.StartNewService(encryptedData);
                        Console.ReadKey();
                    }
                    */
                }
            }

            Console.WriteLine("Press any key to exit...");
            Console.ReadKey();
        }
    }
}
