using System;
using System.Collections.Generic;
using System.Linq;
using System.ServiceModel;
using System.Text;
using System.Threading.Tasks;

namespace Contract
{
    [ServiceContract]
    public interface IAuditContract
    {
        [OperationContract]
        void TestCommunication();

        [OperationContract]
        void LogAuthorizationFailed(string username, string serviceName, string reason);

        [OperationContract]
        void LogServiceStarted(string username);

        [OperationContract]
        void LogServiceStartDenied();
    }
}
