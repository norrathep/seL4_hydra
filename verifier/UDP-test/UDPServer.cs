using System;
using System.Net;
using System.Runtime.InteropServices;
using System.Diagnostics;
using System.Net.Sockets;



namespace UDPtest
{
    public class UDPServer
    {
        public static bool DEBUG = false;
        //public static int CLIENT_PORT = 3000;
        public static int CLIENT_ATTESTATION_PORT = 2000;
        public static int CLIENT_UPDATE_PORT = 3000;
        public static int SERVER_ATTESTATION_PORT = 10000;
        public static int SERVER_UPDATE_PORT = 11000;

        public static int NONCE_LENGTH = 32; // in bytes - now 256 bits nonce
        public static int HASH_LENGTH = 32;
        public static int REQUEST_LENGTH = 8 + NONCE_LENGTH + 8; // in bytes - timestamp | nonce | start_loc | length
        public static int ATT_REQUEST_LENGTH = REQUEST_LENGTH + HASH_LENGTH; // in bytes - timestamp | nonce | start_loc | length | MAC
        UdpClient attestServer = null;
        UdpClient updateServer = null;
        string CLIENT_IP = "192.168.168.2";
        //IPEndPoint client_ep = null;
        LocalIPC lipc = null;

        public void Send(byte[] dgram, int bytes, int server_port, int client_port)
        {
            //UdpClient udpServer = new UdpClient(server_port);

            IPEndPoint client_ep = new IPEndPoint(IPAddress.Parse(CLIENT_IP), client_port);
            if (server_port == SERVER_ATTESTATION_PORT) attestServer.Send(dgram, bytes, client_ep);
            else if (server_port == SERVER_UPDATE_PORT) updateServer.Send(dgram, bytes, client_ep);
            else Console.WriteLine("Invalid server port: " + server_port);
            //udpServer.Close();
        }

        public void LocalSend(byte[] dgram, int bytes)
        {
            lipc.send(dgram, bytes, 1);
        }

        public byte[] LocalReceive()
        {
            return lipc.listen();
        }

        public byte[] Receive(int serverPort)
        {
            var remoteEP = new IPEndPoint(IPAddress.Any, serverPort);
            try
            {
                if (serverPort == SERVER_ATTESTATION_PORT) return attestServer.Receive(ref remoteEP);
                else if (serverPort == SERVER_UPDATE_PORT) return updateServer.Receive(ref remoteEP);
                else
                {
                    Console.WriteLine("Invalid server port: " + serverPort);
                    return null;
                }
            }
            catch (Exception e)
            {
                Console.WriteLine("Timeout!");
            }
            return null;
        }


		private static void ntoha(byte[] input, byte[] output, int len) {

			Debug.Assert(len%4 == 0);
			for(int i=0; i<len; i+=4) {

				int tmp = IPAddress.NetworkToHostOrder(BitConverter.ToInt32(input, i));
				Buffer.BlockCopy (BitConverter.GetBytes (tmp), 0, output, i, 4);
			}
		}

		private static void htona(byte[] input, byte[] output, int len) {

			Debug.Assert(len%4 == 0);
			for(int i=0; i<len; i+=4) {

				int tmp = IPAddress.HostToNetworkOrder(BitConverter.ToInt32(input, i));
				Buffer.BlockCopy (BitConverter.GetBytes (tmp), 0, output, i, 4);
			}
		}

		public static long timestamp_ns() {
			long timestamp = DateTime.Now.Ticks;
			return timestamp;
		}

        public static long DELTA = 0;

		public static long delay_timestamp_ns(int secs) {
			long ts = timestamp_ns ()+DELTA;
            if(DELTA != 0)  Console.WriteLine("Timestamp Delayed by 30 seconds");
			System.Threading.Thread.Sleep (secs * 1000);
			return ts;
		}

        public UDPServer(int server_port)
        {
            //client_ep = new IPEndPoint(IPAddress.Parse(CLIENT_IP), CLIENT_PORT);
            //udpServer = new UdpClient(server_port);
            attestServer = new UdpClient(SERVER_ATTESTATION_PORT);
            updateServer = new UdpClient(SERVER_UPDATE_PORT);

            lipc = new LocalIPC(3005, 3006);
        }

        public UDPServer(int server_port, int recv_timeout) {
            //client_ep = new IPEndPoint (IPAddress.Parse (CLIENT_IP), CLIENT_PORT);

            attestServer = new UdpClient(SERVER_ATTESTATION_PORT);
            updateServer = new UdpClient(SERVER_UPDATE_PORT);
            //updateServer.Client.ReceiveTimeout = recv_timeout;

            lipc = new LocalIPC (3005, 3006);
		}

		[DllImport("msvcrt.dll", CallingConvention = CallingConvention.Cdecl)]
		private static extern int memcmp (byte[] arr1, byte[] arr2, int cnt);

		/*public bool receive_attestation(byte[] gt) {
			Console.WriteLine ("\n\nWaiting for response");
			var remoteEP = new IPEndPoint (IPAddress.Any, 11000);
			try {
				byte[] data = udpServer.Receive (ref remoteEP);
				ntoha(data, data, data.Length);
                if (DEBUG) Console.WriteLine("Receive " + BitConverter.ToString(data) +" from " + remoteEP.ToString());
                if (DEBUG) Console.WriteLine ("Timestamp: " + timestamp_ns().ToString("X"));
				return data.Length == gt.Length && (memcmp(gt, data, gt.Length) == 0);
			} catch(Exception e) {
				Console.WriteLine ("Timeout!");
			}
			return false;
		}*/

		/*
		 * Convert int 2 array of bytes
		 * Reverse the order if its little endian
		 */
		private byte[] int2array(int val) {
			byte[] res = BitConverter.GetBytes (val);
			if (BitConverter.IsLittleEndian)
				Array.Reverse (res);
			return res;
		}

		private byte[] long2array(long val) {
			byte[] res = BitConverter.GetBytes (val);
			if (BitConverter.IsLittleEndian)
				Array.Reverse (res);
			return res;
		}
		public struct attestation_request_header {
			public long timestamp;
			public byte[] nonce;
		}
		public struct attestation_request
		{
			public attestation_request_header header;
			public byte[] mac;

		}

		/*public byte[] send_attestation_request(int start_loc, int length) {
			// generate nonce
			RandomBufferGenerator rbg = new RandomBufferGenerator (REQUEST_LENGTH * 2);
			byte[] request = new byte[REQUEST_LENGTH];
			byte[] nonce = rbg.GenerateBufferFromSeed(NONCE_LENGTH);

			// construct request: timestamp | nonce | start_loc | length
			int offset = 0;
			long timestamp = delay_timestamp_ns(0);
			Buffer.BlockCopy(long2array(timestamp), 0, request, offset, sizeof(long));
            if (DEBUG) Console.WriteLine ("Timestamp: " + timestamp.ToString("X"));
			offset += sizeof(long);

			Buffer.BlockCopy(nonce, 0, request, offset, NONCE_LENGTH);
            if (DEBUG) Console.WriteLine("Nonce: "+BitConverter.ToString(nonce));
			offset += NONCE_LENGTH;

			Buffer.BlockCopy (int2array (start_loc), 0, request, offset, sizeof(int));
			offset += sizeof(int);
			Buffer.BlockCopy (int2array (length), 0, request, offset, sizeof(int));

            if (DEBUG) Console.WriteLine("Request: "+BitConverter.ToString(request));

            // compute MAC(request)
            if (DEBUG) Console.WriteLine ("request len: " + REQUEST_LENGTH);
			lipc.send (request, REQUEST_LENGTH, 1);
			byte[] mac = lipc.listen ();
            if (DEBUG) Console.WriteLine("receive MAC");
			Debug.Assert (mac.Length == HASH_LENGTH);

			// att request: request | mac
			byte[] att_request = new byte[REQUEST_LENGTH+HASH_LENGTH];
			offset = 0;
			Buffer.BlockCopy (request, 0, att_request, offset, REQUEST_LENGTH);
			offset += REQUEST_LENGTH;
			Buffer.BlockCopy (mac, 0, att_request, offset, HASH_LENGTH);

			byte[] gt = lipc.listen ();

            // TODO: I should use these but have to fix the prover tooo


            // send request
            //udpServer.Send(request, REQUEST_LENGTH, client_ep);
            IPEndPoint client_ep = new IPEndPoint(IPAddress.Parse(CLIENT_IP), CLIENT_ATTESTATION_PORT);
            udpServer.Send(att_request, ATT_REQUEST_LENGTH, client_ep);

			return gt;
		}*/
			

		/*public static void Main (string[] args)
		{
			long cur_ts = DateTime.Now.Ticks;
            UDPServer server = new UDPServer (11000, 5000); // timeout for recv = 5 secs
            Console.WriteLine("================= REMOTE ATTESTATION VERIFIER =================");
			Console.WriteLine("Magic Number is 2152 and 1570");
			while (true) {
				Console.Write ("\nStart Attested Memory Location: ");
                string input = Console.ReadLine();
                if(input[0] == 'a')
                {
                    Console.WriteLine("Delaying Timestamp to Timestamp + 30 seconds");
                    DELTA = 30*10 ^ 9;
                    continue;
                }
				int start_loc = Convert.ToInt32 (input);
				Console.Write ("Length: ");
				int length = Convert.ToInt32 (Console.ReadLine ());
				byte[] gt = server.send_attestation_request (start_loc, length);
				bool correct = server.receive_attestation (gt);
                Console.WriteLine("Press Enter to see the result");
                Console.ReadLine();
                Console.WriteLine ("Attestation Succeeds? " + correct);
                DELTA = 0;
			}
		}*/
	}
}

