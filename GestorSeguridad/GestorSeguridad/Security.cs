using Gabriel.Cat.S.Binaris;
using Gabriel.Cat.S.Extension;
using Gabriel.Cat.S.Seguretat;
using ServicioDeSerguridad;
using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;

namespace GestorSeguridad
{
    public static class Security
    {
        public static int NumItemsKey = 100;
        public static string Id { get; set; } = Environment.CurrentDirectory;
        public static async Task<byte[]> GetFile(string pathFile)
        {
            return await GetData(File.ReadAllBytes(pathFile), false);
        }
        public static async Task SetFile(string pathFile,byte[] data)
        {
           (await GetData(data, true)).Save(pathFile);
        }
        public static async Task<byte[]> GetData(byte[] data,bool encrypt=true)
        {
            return await SendData(data, encrypt);
        }
         static async Task<byte[]> SendData(byte[] binData, bool encrypt = true, bool isAKey = false)
        {
            const int PUERTO = 13000;
            byte[] bytes;
            Data data = new Data() { Id = Id, DataBase64 = Convert.ToBase64String(binData), Cifrar = encrypt, IsAKey = isAKey };
            IPAddress localAddr = IPAddress.Parse("127.0.0.1");
            TcpClient client = new TcpClient(localAddr.ToString(), PUERTO);
            NetworkStream stream=null;
            try
            {
                stream = client.GetStream();

                bytes = data.GetBytes();
                stream.Write(bytes, 0, bytes.Length);
                bytes = Data.GetData(stream.GetBytes()).Datos;
            }
            finally
            {
                stream?.Close();
                client.Close();
            }
            return bytes;
        }

        //lo de instalar solo se tiene que hacer una vez
        public static async Task<Key> InstallKey()
        {
            Key key = Key.GetKey(NumItemsKey);
            await InstallKey(key);
            return key;
        }
         public static async Task InstallKey(Key key)
        {
            KeyBinario serializador = new KeyBinario();
            await SendData(serializador.GetBytes(key), false, true);
        }
    }
}
