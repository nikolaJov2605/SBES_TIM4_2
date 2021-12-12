using Manage;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Principal;
using System.ServiceModel;
using System.Text;
using System.Threading.Tasks;

namespace Client
{
    class Program
    {
        static void Main(string[] args)
        {
            NetTcpBinding binding = new NetTcpBinding();
            string address = "net.tcp://localhost:8888/WCFService";

            //Windows autetifikacija vezbe 1 /2 
            binding.Security.Mode = SecurityMode.Transport;
            binding.Security.Transport.ClientCredentialType = TcpClientCredentialType.Windows;
            binding.Security.Transport.ProtectionLevel = System.Net.Security.ProtectionLevel.EncryptAndSign;

            using (MakeClient proxy = new MakeClient(binding, new EndpointAddress(new Uri(address))))
            {
                Console.WriteLine(WindowsIdentity.GetCurrent().Name);
                string key = proxy.Connect();
                Console.WriteLine(key);

                if(!key.Equals(string.Empty)) //Access denied. Program pukne jer kljuc ne odgovara
                {
                    string data;
                    AES_CBC.EncryptData("MortalKombat,8080,TCP ", key, out data);
                    Console.WriteLine(data);
                    proxy.StartNewService(data);
                }
            }

            Console.ReadLine();
        }
    }
}
