using System;
using System.Collections.Generic;
using System.Linq;
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
            string address = "net.tcp://localhost:8888/ServiceManager";

            //Windows autetifikacija vezbe 1 /2 
            //binding.Security.Mode = SecurityMode.Transport;
            //binding.Security.Transport.ClientCredentialType = TcpClientCredentialType.Windows;
            //binding.Security.Transport.ProtectionLevel = System.Net.Security.ProtectionLevel.EncryptAndSign;

            using (MakeClient proxy = new MakeClient(binding, address))
            {
                string key = proxy.Connect();
                Console.WriteLine(key);
            
            }

            Console.ReadLine();
        }
    }
}
