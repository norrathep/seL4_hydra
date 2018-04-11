using System;
using System.Net;
using System.Net.Sockets;
using System.Net.NetworkInformation;
using Chaos.NaCl;
using System.Runtime.InteropServices;

namespace UDPtest
{
	class MainClass
    {

        private const int NUM_APPS = 2;
        private const int NUM_ROOT_KEYS = 4;
        private const int NUM_ROLES = 4;
        public enum Keytype_t { ED25519 };
        public enum RoleType_t { ROOT, SNAPSHOT, TARGET, TIMESTAMP };
        public enum HashType_t { SHA256 };

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct Key_t
        {
            public UInt32 key_id;
            public Keytype_t type;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
            public byte[] public_key;
        };

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct Signature_t
        {
            public UInt32 key_id;
            public Keytype_t type;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 64)]
            public byte[] sig;
        };

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct Role_t
        {
            public RoleType_t type;
            public UInt32 key_id;
            public byte threshold;
        };

        // sizeof(FileMeta) = 16+4+64+1+4 = 89
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct FileMeta_t
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public byte[] name;
            public HashType_t hash_type;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 64)]
            public byte[] hash;
            public byte len;
            public UInt32 version;
        };


        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct RootRequest_t
        {
            public Signature_t signature;
            public RoleType_t role_type;
            public UInt64 timestamp; // TODO: get no-padding here
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = NUM_ROOT_KEYS)]
            public Key_t[] keys;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = NUM_ROLES)]
            public Role_t[] roles; // root, snapshot, targets, and timestamp - assume each role has 1 key
            public UInt32 version;
        };
            
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct SnapshotRequest_t
        {
            public Signature_t signature;
            public RoleType_t role_type;
            public UInt64 timestamp; // TODO: get no-padding here
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
            public FileMeta_t[] meta; // targets and root
            public UInt32 version;
        };
            
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct TargetRequest_t
        {
            public Signature_t signature;
            public RoleType_t role_type;
            public UInt64 timestamp; // TODO: get no padding here
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = NUM_APPS)]
            public FileMeta_t[] meta;
            public UInt32 version;
        };
        
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct TimeStampRequest_t
        {
            public Signature_t signature;
            public RoleType_t role_type;
            public UInt64 timestamp;
            public FileMeta_t meta; // snapshot
            public UInt32 version;
        };


        public struct Image_t {
            public byte[] img;
            public int imgSize;
            public UInt32 version;
            public UInt32 processId; // or name
            public UInt32 start_disk_addr;
            public UInt32 start_cpio_addr;
        };

        [DllImport("msvcrt.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern int memcmp(byte[] arr1, byte[] arr2, int cnt);

        public static int getEntryPoint(Image_t image)
        {
            if (image.img == null) return -1;
            // Magic number: 01 40 2d e9
            for(int i=0; i<image.imgSize; i++)
            {
                if (image.img[i] == 0x01 && image.img[i + 1] == 0x40 && image.img[i + 2] == 0x2d && image.img[i + 3] == 0xe9) return i;
            }
            return -1;
        }

        public static bool performRemoteAttestation(Image_t image, UDPServer server)
        {
            RandomBufferGenerator rbg = new RandomBufferGenerator(UDPServer.REQUEST_LENGTH * 2);
            byte[] request = new byte[UDPServer.REQUEST_LENGTH];
            //byte[] nonce = rbg.GenerateBufferFromSeed(UDPServer.NONCE_LENGTH);

            byte[] buffer = new byte[1000];

            int offset = 0;

            // Plaintext: timestamp(8) (|| nonce) || processId(4)
            offset = 0;
            long timestamp = DateTime.Now.Ticks;
            Buffer.BlockCopy(BitConverter.GetBytes(timestamp), 0, buffer, offset, 8);
            offset += 8;
            //Buffer.BlockCopy(nonce, 0, nonce, offset, nonce.Length);
            //offset += nonce.Length;
            //Buffer.BlockCopy(BitConverter.GetBytes(start_loc), 0, buffer, offset, 8);
            //offset += 8;
            Buffer.BlockCopy(BitConverter.GetBytes(image.processId), 0, buffer, offset, 4);
            offset += 4;
            int bufferSize = offset;

            //Console.WriteLine("Mac Data: " + BitConverter.ToString(buffer, 0, bufferSize));

            // get MAC from LocalIPC
            server.LocalSend(buffer, bufferSize);
            byte[] mac = server.LocalReceive();
            if (mac.Length != 32)
            {
                Console.WriteLine("sth is wrong");
            }

            // Attest Request: MAC || Plaintext
            byte[] attestRequest = new byte[mac.Length + bufferSize];
            offset = 0;
            Buffer.BlockCopy(mac, 0, attestRequest, 0, mac.Length);
            offset += mac.Length;
            Buffer.BlockCopy(buffer, 0, attestRequest, offset, bufferSize);
            offset += bufferSize;

            int requestSize = offset;
            server.Send(attestRequest, requestSize, UDPServer.SERVER_ATTESTATION_PORT, UDPServer.CLIENT_ATTESTATION_PORT);

            
            Console.WriteLine(BitConverter.ToString(attestRequest, 0, requestSize));

            Console.WriteLine("\n\nWaiting for Attestation Report");

            byte[] data = server.Receive(UDPServer.SERVER_ATTESTATION_PORT);
            //Console.WriteLine("Receive " + BitConverter.ToString(data));

            int attestSize = 8 * 4096; // Assume fixed size of attested memory TODO: be more flexible
            byte[] deviceMem = new byte[bufferSize + attestSize];
            int entryPoint = getEntryPoint(image);
            //Console.WriteLine("entry point of img: " + getEntryPoint(image));
            offset = 0;
            Buffer.BlockCopy(buffer, 0, deviceMem, offset, bufferSize);
            offset += bufferSize;
            Buffer.BlockCopy(image.img, entryPoint, deviceMem, offset, attestSize);
            offset += attestSize;

            server.LocalSend(deviceMem, deviceMem.Length);
            byte[] gt = server.LocalReceive();
            //Console.WriteLine("GT " + BitConverter.ToString(gt));
            //Console.ReadLine();
            return data.Length == gt.Length && (memcmp(gt, data, gt.Length) == 0);
        }
        public static void sendFakeRequest(UDPServer server)
        {
            byte[] fakeRequest = new byte[212];

            server.Send(fakeRequest, 212, UDPServer.SERVER_UPDATE_PORT, UDPServer.CLIENT_UPDATE_PORT);

        }
        public static byte[] getBytes(TimeStampRequest_t str)
        {
            int size = Marshal.SizeOf(str);
            Console.WriteLine("Size of str: " + size);
            byte[] arr = new byte[size];

            IntPtr ptr = Marshal.AllocHGlobal(size);
            Marshal.StructureToPtr(str, ptr, true);
            Marshal.Copy(ptr, arr, 0, size);
            Marshal.FreeHGlobal(ptr);
            return arr;
        }
        public static bool sendTufRequest(UDPServer server)
        {
            byte[] tmp = new byte[4];
            server.LocalSend(tmp, 0); // send TimestampRequest_t
            byte[] timestampRequest = server.LocalReceive();
            Console.WriteLine("tsReq: " + BitConverter.ToString(timestampRequest));
            server.Send(timestampRequest, timestampRequest.Length, UDPServer.SERVER_UPDATE_PORT, UDPServer.CLIENT_UPDATE_PORT);

            server.Receive(UDPServer.SERVER_UPDATE_PORT);
            Console.ReadLine();

            server.LocalSend(tmp, 1); // send Snapshot request
            byte[] snapshotRequest = server.LocalReceive();
            Console.WriteLine("shReq: " + BitConverter.ToString(snapshotRequest));
            server.Send(snapshotRequest, snapshotRequest.Length, UDPServer.SERVER_UPDATE_PORT, UDPServer.CLIENT_UPDATE_PORT);

            server.Receive(UDPServer.SERVER_UPDATE_PORT);
            Console.ReadLine();

            server.LocalSend(tmp, 2); // send Target Request
            byte[] targetRequest = server.LocalReceive();
            Console.WriteLine("tgReq: " + BitConverter.ToString(targetRequest));
            server.Send(targetRequest, targetRequest.Length, UDPServer.SERVER_UPDATE_PORT, UDPServer.CLIENT_UPDATE_PORT);


            Console.WriteLine("Done");
            Console.ReadLine();


            byte[] img = System.IO.File.ReadAllBytes("../../../images/fuel-level-app-v0");
            int imgSize = img.Length;
            Console.WriteLine("Sending first img");
            sendImage(img, imgSize, server);
            Console.ReadLine();

            byte[] img2 = System.IO.File.ReadAllBytes("../../../images/speedometer-app-v0");
            int img2Size = img2.Length;
            Console.WriteLine("Sending second img");
            sendImage(img2, img2Size, server);

            server.LocalSend(tmp, 3); // send Root Request
            byte[] rootRequest = server.LocalReceive();
            return true;
        }
        public static bool sendUpdateRequest(Image_t image, UDPServer server)
        {

            byte[] buffer = new byte[image.imgSize + 1000];

            // hash the image
            byte[] hash = Sha512.Hash(image.img, 0, image.imgSize);
            var seed = new byte[32]; // empty seed
            byte[] pk, sk;
            Ed25519.KeyPairFromSeed(out pk, out sk, seed);

            int offset = 0;
            UInt32 processId = image.processId;
            UInt32 version = image.version;
            UInt32 start_disk_addr = image.start_disk_addr, start_cpio_addr = image.start_cpio_addr;

            // Data that should be signed.... : For now - Start-Disk-Addr || Start-Cpio-Addr || Version || Img Size || Process ID || hash
            int metadataLen = sizeof(int) * 5;
            int sigDataLen = hash.Length + metadataLen;
            byte[] sigData = new byte[sigDataLen];
            Buffer.BlockCopy(BitConverter.GetBytes(start_disk_addr), 0, sigData, offset, 4);
            offset += 4;
            Buffer.BlockCopy(BitConverter.GetBytes(start_cpio_addr), 0, sigData, offset, 4);
            offset += 4;
            Buffer.BlockCopy(BitConverter.GetBytes(version), 0, sigData, offset, 4);
            offset += 4;
            Buffer.BlockCopy(BitConverter.GetBytes(image.imgSize), 0, sigData, offset, 4);
            offset += 4;
            Buffer.BlockCopy(BitConverter.GetBytes(processId), 0, sigData, offset, 4);
            offset += 4;
            Buffer.BlockCopy(hash, 0, sigData, offset, hash.Length);
            offset += hash.Length;
            byte[] sig = Ed25519.Sign(sigData, sk);

            // Update Request : MAC(32) || (Timestamp ||) SigData(84)
            // (|| PK Cert || Expire || Hash/SigAlg) || Hash(Img)(64)  || Signature(64) || Public Key(32) 
            offset = 0;
            Buffer.BlockCopy(sigData, 0, buffer, offset, sigDataLen);
            offset += sigDataLen;
            Buffer.BlockCopy(sig, 0, buffer, offset, sig.Length);
            //Console.WriteLine("Sig: " + BitConverter.ToString(sig));
            offset += sig.Length;
            Buffer.BlockCopy(pk, 0, buffer, offset, pk.Length);
            //Console.WriteLine("PK: " + BitConverter.ToString(pk));
            offset += pk.Length;
            int bufferSize = offset;

            //Console.WriteLine("Mac Data: " + BitConverter.ToString(buffer, 0, bufferSize) + " Len: "+bufferSize);

            // get MAC from LocalIPC
            server.LocalSend(buffer, bufferSize);
            byte[] mac = server.LocalReceive();
            if (mac.Length != 32)
            {
                Console.WriteLine("sth is wrong");
            }
            byte[] updateRequest = new byte[mac.Length + bufferSize];
            offset = 0;
            Buffer.BlockCopy(mac, 0, updateRequest, 0, mac.Length);
            offset += mac.Length;
            Buffer.BlockCopy(buffer, 0, updateRequest, offset, bufferSize);
            offset += bufferSize;

            int requestSize = offset;

            server.Send(updateRequest, requestSize, UDPServer.SERVER_UPDATE_PORT, UDPServer.CLIENT_UPDATE_PORT);

            return true;
            /*byte[] recv = server.Receive(UDPServer.SERVER_UPDATE_PORT);
            // TODO: what is the best way to handle packet drops/losses?
            if (recv == null)
            {
                return false;
            }
            return true;*/
        }

        public static void sendImage(byte[] img, int imgSize, UDPServer server)
        {

            int chunckSize = 4000;
            int numChunks = (int)Math.Ceiling((double)imgSize / chunckSize);
            int imgOffset = 0;
            int offset = 0;

            Console.WriteLine("Transmitting...");

            byte[] buffer = new byte[chunckSize + 4];
            for (int i = 0; i < numChunks; i++)
            {
                byte[] recv = server.Receive(UDPServer.SERVER_UPDATE_PORT);
                // TODO: what is the best way to handle packet drops/losses?
                if (recv == null)
                {
                    Console.WriteLine("Connection Lost. Update is over.");
                    return;
                    //server.Send(buffer, offset, UDPServer.SERVER_UPDATE_PORT, UDPServer.CLIENT_UPDATE_PORT);
                    //i--;
                    //continue;
                }
                Array.Clear(buffer, 0, chunckSize);

                int copySize = chunckSize;
                if (imgOffset + chunckSize > imgSize) copySize = imgSize - imgOffset;

                offset = 0;
                Buffer.BlockCopy(BitConverter.GetBytes(IPAddress.HostToNetworkOrder(copySize)), 0, buffer, offset, 4);
                offset += 4;

                Buffer.BlockCopy(img, imgOffset, buffer, offset, copySize);
                imgOffset += copySize;
                offset += copySize;
                System.Threading.Thread.Sleep(100);
                server.Send(buffer, offset, UDPServer.SERVER_UPDATE_PORT, UDPServer.CLIENT_UPDATE_PORT);
                Console.WriteLine("Trasmit: " + offset + " bytes");

            }
            Console.WriteLine("Transmission completed");
        }

        public static void Main (string[] args)
        {

            UDPServer server = new UDPServer(11000, 5000); // timeout for recv = 5 secs
            Console.WriteLine("Verifier");
            Key_t k = new Key_t();
            FileMeta_t fm = new FileMeta_t();
            TargetRequest_t tr = new TargetRequest_t();
            RootRequest_t rr = new RootRequest_t();
            SnapshotRequest_t sr = new SnapshotRequest_t();
            TimeStampRequest_t tsr = new TimeStampRequest_t();
            Console.WriteLine("Size: " + Marshal.SizeOf(tr) +" " + Marshal.SizeOf(rr) + " " + Marshal.SizeOf(sr) + " " + Marshal.SizeOf(tsr));
            Console.WriteLine("Size: " + sizeof(byte));
            while (true)
            {
                Console.Write("Select task: (1) Software Update, (2) Remote Attestation: ");
                String task = Console.ReadLine();
                Console.Write("Select a target process: (1) Fuel Level, (2) Speed: ");
                Image_t image = default(Image_t);
                image.processId = Convert.ToUInt32(Console.ReadLine());

                String fp = "../../";
                String image_name = "";
                if (image.processId == 1)
                {
                    image_name = "fuel-level-app";
                    fp += "fuel-level-app";
                    image.start_cpio_addr = 0;
                    image.start_disk_addr = 0;
                }
                else if (image.processId == 2)
                {
                    image_name = "speedometer-app";
                    fp += "speedometer-app";
                    image.start_cpio_addr = 0;// 477876;
                    image.start_disk_addr = 0;
                }
                else {
                    Console.WriteLine("Invalid Process: " + image.processId);
                    continue;
                }
                Console.Write("Select a version: (0), (1), (2) or (10) for fake request: ");
                image.version = Convert.ToUInt32(Console.ReadLine());
                if (image.version == 10)
                {
                    sendFakeRequest(server);
                    continue;
                }
                if (image.version > 2)
                {
                    Console.WriteLine("Invalid Version: " + image.version);
                    continue;
                }
                fp += "-v" + image.version;
                //Console.WriteLine("Loading file at: " + fp);
                image.img = System.IO.File.ReadAllBytes(fp);
                image.imgSize = image.img.Length;
                if (task == "1") // software update
                {
                    //if(sendUpdateRequest(image, server))    sendImage(image.img, image.imgSize, server);
                    sendTufRequest(server);
                }
                else if (task == "2")
                {
                    Console.WriteLine("Attestation Result: " + performRemoteAttestation(image, server));
                    //Console.WriteLine("Attestation Result: Prover is "+ (performRemoteAttestation(image, server) ? "" : "NOT") + " running "+image_name+" version "+image.version);
                    //if (!performRemoteAttestation(image, server)) Console.WriteLine("Prover does not run the correct software");
                    //else Console.WriteLine("Prover is healthy");
                }
            }
            

		}
	}

}
