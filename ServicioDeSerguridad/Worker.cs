using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Gabriel.Cat.S.Binaris;
using Gabriel.Cat.S.Extension;
using Gabriel.Cat.S.Seguretat;
using Gabriel.Cat.S.Utilitats;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace ServicioDeSerguridad
{
    public class Worker : BackgroundService
    {
        const int MASTERKEYS = 100;
        const string EXTENSIONKEY = ".key";
        const string MASTERKEYFILE = "master"+EXTENSIONKEY;
        const char CARACTERSPLIT = '&';
        const string IDSLIST = "ids.list";
        const string FOLDER = "KEYS";
        private readonly ILogger<Worker> _logger;
        LlistaOrdenada<string, Key> DicKeys;
        byte[] MsgKeyNotInstalled;
        byte[] MsgKeyInstalledSuccessfully;
        Key MasterKey;

        public Worker(ILogger<Worker> logger)
        {
        
            _logger = logger;
            DicKeys = new LlistaOrdenada<string, Key>();
            MsgKeyNotInstalled = System.Text.ASCIIEncoding.ASCII.GetBytes("Key not installed!");
            MsgKeyInstalledSuccessfully = System.Text.ASCIIEncoding.ASCII.GetBytes("Key installed successfully!");
            //cargo las que ya tenia
            LoadKeys();
        }



        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            
            Int32 port;
            IPAddress localAddr;
            TcpClient client;
            Byte[] bytes;
            NetworkStream stream;
            byte[] msg;
            Data data;
            TcpListener server = default;

            try
            {
                // Set the TcpListener on port 13000.
                port = 13000;
                localAddr = IPAddress.Parse("127.0.0.1");

                // TcpListener server = new TcpListener(port);
                server = new TcpListener(localAddr, port);

                // Start listening for client requests.
                server.Start();

                // Buffer for reading data
                bytes = new byte[1024];
                data = default;

                // Enter the listening loop.
                while (!stoppingToken.IsCancellationRequested)
                {
                    Console.Write("Waiting for a connection... ");

                    // Perform a blocking call to accept requests.
                    // You could also user server.AcceptSocket() here.
                    client = await server.AcceptTcpClientAsync();
                    Console.WriteLine("Connected!");

                    data = default;

                    // Get a stream object for reading and writing
                    stream = client.GetStream();

                    data = Data.GetData(stream.GetBytes());


                    if (data.IsAKey)
                        {
                            DicKeys.AddOrReplace(data.Id, data.Key);
                            msg = MsgKeyInstalledSuccessfully;
                        }
                        else if(DicKeys.ContainsKey(data.Id))
                        {
                            //quiere cifrar o descifrar
                            if(data.Cifrar)
                                msg = DicKeys[data.Id].Encrypt(data.Datos);
                            else
                                msg = DicKeys[data.Id].Decrypt(data.Datos);


                        }
                        else
                        {
                            msg = MsgKeyNotInstalled;
                        }
                        msg = Data.GetResponse(data.Id, msg);
                        // Send back a response.
                        stream.Write(msg, 0, msg.Length);
                   

                    // Shutdown and end connection
                    client.Close();
                }
            }
            catch (SocketException e)
            {
                Console.WriteLine("SocketException: {0}", e);
            }
            finally
            {
                if(server!=default)
                // Stop listening for new clients.
                   server.Stop();

                SaveKeys();
            }

        }

        private void SaveKeys()
        {
            string aux;
            string dir = Path.GetTempFileName();
            StringBuilder namesList = new StringBuilder();
            KeyBinario serializadorKeys = new KeyBinario();
            ElementoBinario stringSerialitzer = ElementoBinario.GetSerializador<string>();

            aux = Path.Combine(dir, MASTERKEYFILE);
            serializadorKeys.GetBytes(MasterKey).Save(aux);//como aun  no tiene asignada la MasterKey puedo usar este serializador
            File.Encrypt(aux);

            stringSerialitzer.Key = MasterKey;
            serializadorKeys.Key = MasterKey;
            Directory.CreateDirectory(dir);
            foreach(var item in DicKeys)
            {
                aux = Path.GetTempFileName();
                namesList.AppendLine($"{item.Key.EscaparCaracteresXML()}{CARACTERSPLIT}{aux.EscaparCaracteresXML()}");
                aux = Path.Combine(dir, aux + EXTENSIONKEY);
                serializadorKeys.GetBytes(item.Value).Save(aux);
            
            }
            aux = Path.Combine(dir, IDSLIST);
            File.WriteAllBytes(aux,stringSerialitzer.GetBytes(namesList.ToString()));
            if(Directory.Exists(FOLDER))
              Directory.Delete(FOLDER);
            Directory.Move(dir, FOLDER);
        }
        private void LoadKeys()
        {
            string[] names;
            string[] campos;
            KeyBinario serializador = new KeyBinario();
            string[] files = Directory.GetFiles(FOLDER);
            SortedList<string,Key> keys = new SortedList<string, Key>();
            SortedList<string, string> dicNames = new SortedList<string, string>();
            ElementoBinario stringSerialitzer = ElementoBinario.GetSerializador<string>();
            string masterPath = Path.Combine(FOLDER, MASTERKEYFILE);
            if (File.Exists(masterPath))
            {
                File.Decrypt(masterPath);
                MasterKey = serializador.GetObject(File.ReadAllBytes(masterPath)) as Key;
                File.Encrypt(masterPath);

                stringSerialitzer.Key = MasterKey;
                serializador.Key = MasterKey;

                for (int i = 0; i < files.Length; i++)
                {

                    if (Path.GetExtension(files[i]) == EXTENSIONKEY)
                    {
                        keys.Add(Path.GetFileNameWithoutExtension(files[i]), serializador.GetObject(File.ReadAllBytes(files[i])) as Key);
                    }
                    else
                    {
                        names = (stringSerialitzer.GetObject(File.ReadAllBytes(files[i])) as string).Split('\n');
                        for (int j = 0; j < names.Length; j++)
                        {
                            campos = names[j].Split(CARACTERSPLIT);
                            dicNames.Add(campos[0].DescaparCaracteresXML(), campos[1].DescaparCaracteresXML());
                        }
                    }

                }
                foreach (var item in dicNames)
                {
                    DicKeys.Add(item.Key, keys[item.Value]);
                }
            }
            else MasterKey = Key.GetKey(MASTERKEYS);//para la primera vez
          
         
        }
    }
}
