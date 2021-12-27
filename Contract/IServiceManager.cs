﻿using System;
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

    }
}
