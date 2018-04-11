using System;
using System.Net;
using System.Net.Sockets;

namespace UDPtest
{
	public class LocalIPC
	{
		int mylocalport = 3005;
		int listenport = 3006;
		string LOCAL_HOST_IP = "127.0.0.1";
		UdpClient udpServer = null;

		public LocalIPC (int mylocalport, int listenport)
		{
			this.mylocalport = mylocalport;
			this.listenport = listenport;
			udpServer = new UdpClient (this.mylocalport);
		}

		public void send(byte[] data, int size, int delay_in_sec) {

			System.Threading.Thread.Sleep (delay_in_sec*1000);
			if(UDPServer.DEBUG) Console.WriteLine ("Sending\n");
			//byte[] request = System.Text.Encoding.ASCII.GetBytes("hello");
			IPEndPoint client_ep = new IPEndPoint (IPAddress.Parse (LOCAL_HOST_IP), listenport);
			udpServer.Send(data, size, client_ep);
		}

		public byte[] listen() {
            if (UDPServer.DEBUG) Console.WriteLine ("Listening at port " + listenport);

			var remoteEP = new IPEndPoint (IPAddress.Any, listenport);
			byte[] data = udpServer.Receive (ref remoteEP);
            if (UDPServer.DEBUG) Console.WriteLine("Receive " + BitConverter.ToString(data) +" from " + remoteEP.ToString());
			return data;
		}
	}
}

