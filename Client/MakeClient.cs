using Contract;
using System;
using System.Collections.Generic;
using System.Linq;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.Text;
using System.Threading.Tasks;

namespace Client
{
    public class MakeClient : ChannelFactory<IServiceManager>, IServiceManager, IDisposable
    {
        IServiceManager factory;
        public MakeClient(Binding binding, string remoteAddress) : base(binding, remoteAddress)
        {
            factory = this.CreateChannel();
        }
        public MakeClient(Binding binding, EndpointAddress remoteAddress) : base(binding, remoteAddress)
        {
            factory = this.CreateChannel();
        }

        public bool Connect(byte[] encryptedSessionKey)
        {
            bool connected = false;
            try
            {
                connected = factory.Connect(encryptedSessionKey);

            }catch(FaultException<SecurityException> sec)
            {
                Console.WriteLine(sec.Message);

            }catch(Exception e)
            {
                Console.WriteLine(e.Message);
            }
            return connected;
        }

        public bool StartNewService(byte[] encryptedMessage)
        {
            try
            {
                return factory.StartNewService(encryptedMessage);
            }
            catch (FaultException<SecurityException> sec)
            {
                Console.WriteLine(sec.Message);
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }
            return false ;
        }

        public void AddRule(string group, string protocol = "", int port = -1)
        {
            try
            {
                factory.AddRule(group, protocol, port);
                return;
            }
            catch (FaultException<SecurityException> sec)
            {
                Console.WriteLine(sec.Message);
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }
        }

        public void RemoveRule(string group, string protocol = "", int port = -1)
        {
            try
            {
                factory.RemoveRule(group, protocol, port);
                return;
            }
            catch (FaultException<SecurityException> sec)
            {
                Console.WriteLine(sec.Message);
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }
        }

        public void Dispose()
        {
            if (factory != null)
            {
                factory = null;
            }

            this.Close();
        }
    }
}
