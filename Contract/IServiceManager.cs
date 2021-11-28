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
        string Connect();

        [OperationContract]
        [FaultContract(typeof(SecurityException))]
        bool StartNewService(string encryptedMessage);

    }
}
