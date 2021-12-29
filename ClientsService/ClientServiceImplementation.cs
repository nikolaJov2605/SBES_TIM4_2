using Contract;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ClientsService
{
    public class ClientServiceImplementation : IClientsService
    {
        public void PrintInfoService()
        {
            Console.WriteLine("INFO: Service is running.");
        }
    }
}
