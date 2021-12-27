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
        public void LogAuthenticationSuccess(string username)
        {
            try
            {
                Audit.AuthenticationSuccess(username);
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }
        }

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

        public void LogAuthorizationSuccess(string username, string serviceName)
        {
            try
            {
                Audit.AuthorizationSuccess(username, serviceName);
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
