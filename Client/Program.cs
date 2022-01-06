using CertHelper;
using Common;
using Manage;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.ServiceModel;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace Client
{
    class Program
    {
        static void Main(string[] args)
        {
            NetTcpBinding binding = new NetTcpBinding();
            string address = "net.tcp://localhost:8888/WCFService";

            binding.Security.Mode = SecurityMode.Transport;
            binding.Security.Transport.ClientCredentialType = TcpClientCredentialType.Windows;
            binding.Security.Transport.ProtectionLevel = System.Net.Security.ProtectionLevel.EncryptAndSign;

            using (MakeClient proxy = new MakeClient(binding, new EndpointAddress(new Uri(address))))
            {
                bool isConnected = false;
                bool isClosed = false;
                byte[] sessionKey = null;

                while (true)
                {
                    if (!isConnected)
                        Console.WriteLine("1. Connect to SistemManager (SM)");
                    else
                    {
                        Console.WriteLine("2. Run Client Service");
                        Console.WriteLine("3. Add BlackList Rule");
                        Console.WriteLine("4. Remove BlackList Rule");
                    }
                    Console.WriteLine("5. Exit");

                    int input = Int32.Parse(Console.ReadLine());

                    if (isConnected)
                    {
                        switch (input)
                        {
                            case 2:
                                ClientStartService(proxy, sessionKey);
                                break;
                            case 3:
                                ClientAddRule(proxy);
                                break;
                            case 4:
                                ClientRemoveRule(proxy);
                                break;
                            case 5:
                                isClosed = true;
                                break;
                            default:
                                Console.WriteLine("Wrong input!");
                                break;
                        }
                    }
                    else if (!isConnected)
                    {
                        switch (input)
                        {
                            case 1:
                                isConnected = ClientConnect(proxy, out sessionKey);
                                break;
                            case 5:
                                isClosed = true;
                                break;
                            default:
                                Console.WriteLine("Wrong input!");
                                break;
                        }
                    }


                    if (isClosed)
                        break;

                    Console.WriteLine();
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

            Console.WriteLine("Press any key to exit...");
            Console.ReadKey();
        }

        private static bool ClientConnect(MakeClient proxy, out byte[] sessionKey)
        {
            string serviceCert = "Manager";

            Console.WriteLine(WindowsIdentity.GetCurrent().Name);
            sessionKey = SessionKeyHelper.CreateSessionKey();

            X509Certificate2 certificate = CertManager.GetCertificateFromStorage(StoreName.TrustedPeople, StoreLocation.LocalMachine, serviceCert);

            byte[] encryptedSessionKey = SessionKeyHelper.EncryptSessionKey(certificate, sessionKey);

            return proxy.Connect(encryptedSessionKey);
        }

        private static void ClientStartService(MakeClient proxy, byte[] sessionKey)
        {
            string machineStr = "";
            string protocol = "";
            string port = "";
            int portNum = -1;

            do
            {
                Console.WriteLine("Input name of machine: ");
                machineStr = Console.ReadLine().Trim();
            } while (machineStr == "" || machineStr == null || Regex.IsMatch(machineStr, @"^\d+"));

            while (true)
            {
                Console.WriteLine("Input protocol: ");
                protocol = Console.ReadLine();
                ProtocolEnum.Protocols pe;
                bool isConverted = Enum.TryParse<ProtocolEnum.Protocols>(protocol.ToUpper(), out pe);
                if (!isConverted)
                    continue;
                if (Enum.IsDefined(typeof(ProtocolEnum.Protocols), pe))
                    break;
            }

            do
            {
                Console.WriteLine("Input port ");
                port = Console.ReadLine();
                bool isConverted = Int32.TryParse(port, out portNum);
                if (!isConverted)
                    continue;
            } while (port == "" || port == null || portNum > 65535 || portNum < 1023);

            byte[] encryptedData = AES_CBC.EncryptData(string.Format("{0},{1},{2}", machineStr, protocol, port), sessionKey);

            bool isStarted = proxy.StartNewService(encryptedData);

            if (isStarted)
                Console.WriteLine("Service is successfully started.");
            else
                Console.WriteLine("Service is not started due to blacklist configuration.");
        }

        private static void ClientAddRule(MakeClient proxy)
        {
            string userGroup = "";
            string protocol = "";
            string port = "";
            int portNum = -1;
            bool isConverted = false;

            do
            {
                Console.WriteLine("Input name of group: ");
                userGroup = Console.ReadLine().Trim();
            } while (userGroup == "" || userGroup == null);


            do
            {
                // Unos protokola
                do
                {
                    Console.WriteLine("Input protocol: ");
                    protocol = Console.ReadLine();
                    if (protocol == "")
                        break;
                    ProtocolEnum.Protocols pe;
                    isConverted = Enum.TryParse<ProtocolEnum.Protocols>(protocol.ToUpper(), out pe);

                } while (isConverted == false);

                // Unos porta
                do
                {
                    Console.WriteLine("Input port ");
                    port = Console.ReadLine();
                    if (port == "")
                        break;
                    isConverted = Int32.TryParse(port, out portNum);
                    if (!isConverted)
                    {
                        Console.WriteLine("Port must be a number between 1023 and 65535");
                        continue;
                    }
                } while (portNum > 65535 || portNum < 1023);

                if (protocol == "" && port == "")
                {
                    Console.WriteLine("You must define protocol or port");
                }

            } while (protocol == "" && port == "");


            proxy.AddRule(userGroup, protocol, portNum);

        }

        private static void ClientRemoveRule(MakeClient proxy)
        {
            string userGroup = "";
            string protocol = "";
            string port = "";
            int portNum = -1;

            do
            {
                Console.WriteLine("Input name of group: ");
                userGroup = Console.ReadLine().Trim();
            } while (userGroup == "" || userGroup == null);

            while (true)
            {
                Console.WriteLine("Input protocol: ");
                protocol = Console.ReadLine();
                if (protocol == "")
                    break;
                ProtocolEnum.Protocols pe;
                bool isConverted = Enum.TryParse<ProtocolEnum.Protocols>(protocol.ToUpper(), out pe);
                if (!isConverted)
                    continue;
                if (Enum.IsDefined(typeof(ProtocolEnum.Protocols), pe))
                    break;
            }

            do
            {
                Console.WriteLine("Input port ");
                port = Console.ReadLine();
                if (port == "" && protocol != "")
                    break;
                bool isConverted = Int32.TryParse(port, out portNum);
                if (!isConverted)
                    continue;
            } while (port == "" || port == null || portNum > 65535 || portNum < 1023);

            proxy.RemoveRule(userGroup, protocol, portNum);
        }
    }
}
