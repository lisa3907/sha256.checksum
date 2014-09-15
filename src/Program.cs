using System;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;

namespace Sha256Sum
{
    internal class Program
    {
        private static void Main(string[] args)
        {
            if (args.Length > 0)
            {
                try
                {
                    var _fileStream = new FileStream(args[0],
                                       FileMode.Open,
                                       FileAccess.Read);

                    var _hashValue = GetSha512Buffered(_fileStream);

                    Console.WriteLine("file:{0} -> hash: {1}", args[0], _hashValue);
                }
                catch (Exception ex)
                {
                    Console.WriteLine("file:{0} -> error: {1}", args[0], ex.Message);
                }
            }
        }


        /// <summary>
        /// Used so we can get MD5Hash and get progress on calculation
        /// </summary>
        /// <param name="p_streamIn"></param>
        /// <returns></returns>
        public static string GetSha512Buffered(Stream p_streamIn)
        {
            string _result;

            Process.GetCurrentProcess();
            const int _bufferSizeForMd5Hash = 1024 * 1024 * 8;

            using (var _md5Prov = new SHA256Managed())
            {
                int _readCount;
                var _bytesTransfered = 0;
                var _buffer = new byte[_bufferSizeForMd5Hash];

                while ((_readCount = p_streamIn.Read(_buffer, 0, _buffer.Length)) != 0)
                {
                    if (_bytesTransfered + _readCount == p_streamIn.Length)
                    {
                        _md5Prov.TransformFinalBlock(_buffer, 0, _readCount);
                    }
                    else
                    {
                        _md5Prov.TransformBlock(_buffer, 0, _bufferSizeForMd5Hash, _buffer, 0);
                    }
                    _bytesTransfered += _readCount;
                }

                _result = BitConverter.ToString(_md5Prov.Hash).Replace("-", String.Empty).ToLower();
                _md5Prov.Clear();
            }

            return _result;
        }

        public static string GetSha512BufferedStream(Stream p_stream)
        {
            var _bufferedStream = new BufferedStream(p_stream, 1024 * 1024 * 8);
            var _sha256 = new SHA256Managed();

            var _checksum = _sha256.ComputeHash(_bufferedStream);

            var _process = Process.GetCurrentProcess();
            Console.WriteLine("Current Memory In Use: " + _process.PrivateMemorySize64 / 1000000);
            return BitConverter.ToString(_checksum).Replace("-", String.Empty);
        }
    }
}
