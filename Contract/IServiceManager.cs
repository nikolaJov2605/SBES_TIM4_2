using System;
using System.Collections.Generic;
using System.Linq;
using System.ServiceModel;
using System.Text;
using System.Threading.Tasks;

namespace Contract
{
    [ServiceContract]
    public interface IServiceManager
    {
        [OperationContract]
        [FaultContract(typeof(SecurityException))]
        bool Connect(byte[] encryptedSessionKey);

        [OperationContract]
        [FaultContract(typeof(SecurityException))]
        bool StartNewService(byte[] encryptedMessage);

        [OperationContract]
        [FaultContract(typeof(SecurityException))]
        void AddRule(string group, string protocol = "", int port = -1);

        [OperationContract]
        [FaultContract(typeof(SecurityException))]
        void RemoveRule(string group, string protocol = "", int port = -1);
    }
}
