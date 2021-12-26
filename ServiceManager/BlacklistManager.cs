using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Resources;
using System.Text;
using System.Threading.Tasks;

namespace ServiceManager
{
    public class BlacklistManager
    {
        static string path = @"~\..\..\..\..\ServiceManager\Blacklist.resx";

        public static bool PermissionGranted(string[] groups, string protocol, int port)
        {
            string[] pairs, concretePair;
            string pairsStr, pr, por;


            // prodji kroz sve grupe kojima korisnik pripada
            foreach (string group in groups)
            {   // izvuci string sa protokolima:portovima i splituj ga
                pairsStr = (string)Blacklist.ResourceManager.GetObject(group);
                pairs = pairsStr.Split(',');
                foreach (string pair in pairs)
                {   // ako par ne sadrzi ':', znaci da je naveden samo protokol ili samo port
                    if (!pair.Contains(':'))
                    {
                        int portNum;
                        bool isNumber = Int32.TryParse(pair, out portNum);  // ako je unet port, isNumber ce biti true, u suprotnom ce biti false

                        if (isNumber)   // ako se u konfiguraciji nalazi samo port, poredimo ga sa onim koji je prosledjen i odlucujemo odobravamo li pristup ili ne
                        {
                            if (port == portNum)
                                return false;
                        }
                        else            // u suprotnom, ako je u konfiguraciji samo protokol, poredimo ga sa prosledjenim protokolom
                        {
                            if (pair.ToUpper() == protocol.ToUpper())
                                return false;
                        }
                    }
                    else
                    {
                        concretePair = pair.Split(':');
                        pr = concretePair[0];
                        por = concretePair[1];
                        if (protocol.ToUpper() == pr.ToUpper() && port.ToString() == por)
                        {
                            return false;
                        }
                    }
                }
            }


            return true;
        }

        // ako dodajemo pravilo u vidu samo protokola, onda brisemo sva do tad postojeca pravila vezana za taj protokol
        public static void AddRule(string group, string protocol)
        {
            Dictionary<string, string> retDic = new Dictionary<string, string>();

            string pairsStr = (string)Blacklist.ResourceManager.GetObject(group);
            string[] pairs = pairsStr.Split(',');

            pairs = pairs.Where(x => !x.ToUpper().StartsWith(protocol.ToUpper())).ToArray();

            pairs = pairs.Concat(new string[] { protocol.ToUpper() }).ToArray();
            string output = String.Join(",", pairs);

            using (ResXResourceReader rsxr = new ResXResourceReader(path))
            {
                foreach (DictionaryEntry d in rsxr)
                {
                    if (d.Key.ToString() != group)
                        retDic.Add(d.Key.ToString(), d.Value.ToString());
                }
            }
            retDic.Add(group, output);
            using (ResXResourceWriter writer = new ResXResourceWriter(path))
            {
                foreach (KeyValuePair<string, string> kvp in retDic)
                {
                    writer.AddResource(kvp.Key, kvp.Value);
                }
            }
        }

        // ako dodajemo pravilo u vidu samo porta, onda brisemo sva do tad postojeca pravila vezana za taj port
        public static void AddRule(string group, int port)
        {
            Dictionary<string, string> retDic = new Dictionary<string, string>();
            List<string> toDelete = new List<string>();

            string pairsStr = (string)Blacklist.ResourceManager.GetObject(group);
            string[] pairs = pairsStr.Split(',');

            foreach (string pair in pairs)
            {
                if (!pair.Contains(':'))
                {
                    if (pair == port.ToString())        // ako pravilo vec postoji, prekini izvrsavanje
                        break;
                }
                else
                {
                    string[] concretePair = pair.Split(':');
                    if (concretePair[1] == port.ToString())
                        toDelete.Add(pair);
                }
            }
            List<string> tmpList = pairs.ToList();

            foreach (string itemToDelete in toDelete)
            {
                foreach (string item in tmpList.ToList())
                {
                    if (itemToDelete == item)
                    {
                        tmpList.Remove(item);
                    }
                }
            }
            pairs = tmpList.ToArray();

            pairs = pairs.Concat(new string[] { port.ToString() }).ToArray();

            string output = String.Join(",", pairs);

            using (ResXResourceReader rsxr = new ResXResourceReader(path))
            {
                foreach (DictionaryEntry d in rsxr)
                {
                    if (d.Key.ToString() != group)
                        retDic.Add(d.Key.ToString(), d.Value.ToString());
                }
            }
            retDic.Add(group, output);
            using (ResXResourceWriter writer = new ResXResourceWriter(path))
            {
                foreach (KeyValuePair<string, string> kvp in retDic)
                {
                    writer.AddResource(kvp.Key, kvp.Value);
                }
            }
        }
    }
}
