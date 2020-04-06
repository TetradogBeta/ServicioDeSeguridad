using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Sockets;
using System.Text;

namespace Gabriel.Cat.S.Extension
{
   public static class ExtensionNetWorkStream
    {
        public static byte[] GetBytes(this NetworkStream stream)
        {
            int numBytesRead;
            byte[] buffer = new byte[1024];
            byte[] data;
            using (MemoryStream ms = new MemoryStream())
            {
                while ((numBytesRead = stream.Read(buffer, 0, buffer.Length)) > 0)
                {
                    ms.Write(buffer, 0, numBytesRead);


                }
                data = ms.ToArray();
            }
            return data;
        }
    }
}
