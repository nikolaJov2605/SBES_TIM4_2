using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Principal;
using System.ServiceModel;
using System.Text;
using System.Threading.Tasks;
using Contract;

namespace ClientsService
{
    class Program
    {
        static void Main(string[] args)
        {
            string protocol;
            int port;
            if(args[0] != null && args[1] != null)
            {
                protocol = args[0];
                port = Int32.Parse(args[1]);
            }
            else
            {
                Console.WriteLine("No argumets.");
                return;
            }

            NetTcpBinding binding = new NetTcpBinding();
            string address = string.Format("net.tcp://localhost:{0}/IClientService", port);
            ServiceHost host = new ServiceHost(typeof(ClientServiceImplementation));
            host.AddServiceEndpoint(typeof(IClientsService), binding, address);

            try
            {
                host.Open();
                Console.WriteLine("Service started by: {0}", WindowsIdentity.GetCurrent().Name);
                Console.WriteLine("Service is running with protocol: {0}, on port: {1}", protocol, port);
            }
            catch(Exception ex)
            {
                Console.WriteLine("Start failed: {0}", ex.Message);
            }

            Console.ReadKey();
        }
    }
}
