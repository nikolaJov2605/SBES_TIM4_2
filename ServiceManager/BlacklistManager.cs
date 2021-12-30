using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Resources;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace ServiceManager
{
    public class BlacklistManager
    {
        private static string path = @"~\..\..\..\..\ServiceManager\Blacklist.resx";
        private byte[] fileHash;
        private SHA256 shaProvider;

        private static BlacklistManager managerInstance;

        public byte[] FileHash { get => fileHash; }


        private BlacklistManager()
        {
            shaProvider = SHA256.Create();
            fileHash = ComputeHashValue();
        }

        public static BlacklistManager Instance()
        {
            if (managerInstance == null)
            {
                managerInstance = new BlacklistManager();
            }

            return managerInstance;
        }


        public byte[] ComputeHashValue()
        {
            using (FileStream fs = File.OpenRead(path))
            {
                return shaProvider.ComputeHash(fs);
            }
        }


        public bool FileHashValid()
        {
            byte[] currentHashValue;
            using (FileStream fs = File.OpenRead(path))
            {
                currentHashValue = shaProvider.ComputeHash(fs);
            }

            int iterator = 0;
            if (currentHashValue.Length == fileHash.Length)
            {
                while (iterator < currentHashValue.Length && (currentHashValue[iterator] == fileHash[iterator]))
                {
                    iterator++;
                }
                if (iterator == fileHash.Length)
                {
                    return true;
                }
            }

            return false;
        }

        public bool PermissionGranted(string[] groups, string protocol, int port, out string reason)
        {
            string[] pairs, concretePair;
            string pairsStr, pr, por;
            reason = "";


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
                            {
                                reason = "PORT";
                                return false;
                            }
                        }
                        else            // u suprotnom, ako je u konfiguraciji samo protokol, poredimo ga sa prosledjenim protokolom
                        {
                            if (pair.ToUpper() == protocol.ToUpper())
                            {
                                reason = "PROTOCOL";
                                return false;
                            }
                        }
                    }
                    else
                    {
                        concretePair = pair.Split(':');
                        pr = concretePair[0];
                        por = concretePair[1];
                        if (protocol.ToUpper() == pr.ToUpper() && port.ToString() == por)
                        {
                            reason = "PROTOCOL+PORT";
                            return false;
                        }
                    }
                }
            }


            return true;
        }


        #region ADD_RULE_METHODS

        // dodaje pravilo na osnovu dodeljene grupe, protokola i porta
        public void AddRule(string group, string protocol, int port)
        {
            SortedDictionary<string, string> retDic = new SortedDictionary<string, string>();

            string addedPair = protocol.ToUpper() + ":" + port;

            string pairsStr = (string)Blacklist.ResourceManager.GetObject(group);
            string[] pairs = pairsStr.Split(',');

            foreach (string pair in pairs)
            {
                if (pair == addedPair)            // ako definisano pravilo vec postoji, prekini izvrsavanje
                    return;
            }

            pairs = pairs.Concat(new string[] { addedPair }).ToArray();
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

            fileHash = ComputeHashValue();

        }


        // ako dodajemo pravilo u vidu samo protokola, onda brisemo sva do tad postojeca pravila vezana za taj protokol
        public void AddRule(string group, string protocol)
        {
            SortedDictionary<string, string> retDic = new SortedDictionary<string, string>();

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

            fileHash = ComputeHashValue();

        }

        // ako dodajemo pravilo u vidu samo porta, onda brisemo sva do tad postojeca pravila vezana za taj port
        public void AddRule(string group, int port)
        {
            SortedDictionary<string, string> retDic = new SortedDictionary<string, string>();
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

            fileHash = ComputeHashValue();

        }

        #endregion


        #region REMOVE_RULE_METHODS

        // Uklanjanje pravila vezanog za datu grupu u kontekstu protokola i porta
        public void RemoveRule(string group, string protocol, int port)
        {
            Dictionary<string, string> retDic = new Dictionary<string, string>();

            string toDelete = protocol.ToUpper() + ":" + port;

            string pairsStr = (string)Blacklist.ResourceManager.GetObject(group);
            string[] pairs = pairsStr.Split(',');

            List<string> outList = new List<string>();

            foreach (string pair in pairs)
            {
                if (pair != toDelete)
                {
                    outList.Add(pair);
                }
            }
            if (pairs.Count() == outList.Count)         // ako u konfiguraciji ne postoji trazeno pravilo, brojevi elemenata kolekcija pre i 
                return;                                 // posle brisanja ce biti isti i prekinuce se izvrsavanje


            string output = String.Join(",", outList);

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

            fileHash = ComputeHashValue();

        }


        // brisanje pravila vezanog za datu grupu u kontekstu protokola
        public void RemoveRule(string group, string protocol)
        {
            Dictionary<string, string> retDic = new Dictionary<string, string>();


            string pairsStr = (string)Blacklist.ResourceManager.GetObject(group);
            string[] pairs = pairsStr.Split(',');

            List<string> outList = new List<string>();

            foreach (string pair in pairs)
            {
                if (pair != protocol.ToUpper())
                {
                    outList.Add(pair);
                }
            }
            if (pairs.Count() == outList.Count)
                return;


            string output = String.Join(",", outList);

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

            fileHash = ComputeHashValue();

        }


        // brisanje pravila vezanog za datu grupu u kontekstu porta
        public void RemoveRule(string group, int port)
        {
            Dictionary<string, string> retDic = new Dictionary<string, string>();


            string pairsStr = (string)Blacklist.ResourceManager.GetObject(group);
            string[] pairs = pairsStr.Split(',');

            List<string> outList = new List<string>();

            foreach (string pair in pairs)
            {
                if (pair != port.ToString())
                {
                    outList.Add(pair);
                }
            }
            if (pairs.Count() == outList.Count)
                return;


            string output = String.Join(",", outList);

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

            fileHash = ComputeHashValue();

        }

        #endregion


    }
}
