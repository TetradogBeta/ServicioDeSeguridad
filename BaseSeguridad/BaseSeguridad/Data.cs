using Gabriel.Cat.S.Seguretat;
using System;
using System.Collections.Generic;
using System.Text;

namespace ServicioDeSerguridad
{
    public class Data
    {
        public string Id { get; set; }
        public string DataBase64 { get; set; }
        /// <summary>
        /// Si es false es para descifrar
        /// </summary>
        public bool Cifrar { get; set; }
        public bool IsAKey { get; set; }

        public byte[] Datos => Convert.FromBase64String(DataBase64);
        public Key Key =>IsAKey? Gabriel.Cat.S.Binaris.ElementoBinario.GetSerializador<Key>().GetObject(Datos) as Key:null;

        public byte[] GetBytes()
        {
            string json = Newtonsoft.Json.JsonConvert.SerializeObject(this);
            return System.Text.ASCIIEncoding.ASCII.GetBytes(json);
        }

        public static Data GetData(byte[] dataTcp)
        {
            string json = System.Text.ASCIIEncoding.ASCII.GetString(dataTcp);
            return Newtonsoft.Json.JsonConvert.DeserializeObject<Data>(json);
        }
        public static byte[] GetResponse(string id,byte[] data)
        {
            Data response = new Data();
            response.Id = id;
            response.DataBase64 = Convert.ToBase64String(data);
            return response.GetBytes();

        }
     
    }
}
