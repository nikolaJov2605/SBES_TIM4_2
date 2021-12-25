using Contract;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Audit
{
    public class AuditService : IAuditContract
    {
        public void LogAuthorizationFailed(string username, string serviceName, string reason)
        {
            try
            {
                Audit.AuthorizationFailed(username, serviceName, reason);
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }
        }

        public void LogServiceStartDenied()
        {
            try
            {
                Audit.ServiceStartDenied();
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }
        }

        public void LogServiceStarted(string username)
        {
            try
            {
                Audit.ServiceStarted(username);
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }
        }

        public void TestCommunication()
        {
            Console.WriteLine("Communication established.");
        }

    }
}
