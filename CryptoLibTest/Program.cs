using ST.CryptoLib;
using System;

namespace CryptoLibTest
{
    class Program
    {
        static void Main(string[] args)
        {
            string input = "#asd@zyz!}";

            string md5hash = CryptoUtil.MD5Hash(input);
            bool md5Verify= CryptoUtil.MD5Verify(input, md5hash);

            string sha1hash = CryptoUtil.SHA1Hash(input);
            bool sha1Verify = CryptoUtil.SHA1Verify(input, sha1hash);

            string sha256hash = CryptoUtil.SHA256Hash(input);
            bool sha256Verify = CryptoUtil.SHA256Verify(input, sha256hash);

            string sha384hash = CryptoUtil.SHA384Hash(input);
            bool sha384Verify = CryptoUtil.SHA384Verify(input, sha384hash);

            string sha512hash = CryptoUtil.SHA512Hash(input);
            bool sha512Verify = CryptoUtil.SHA512Verify(input, sha512hash);

            string desEncrypt = CryptoUtil.DESEncrypt(input);
            string desDecrypt = CryptoUtil.DESDecrypt(desEncrypt);

            string rsaEncrypt = CryptoUtil.RSAEncrypt(input);
            string rsaDecrypt = CryptoUtil.RSADecrypt(rsaEncrypt);

            Console.ReadLine();
        }
    }
}
