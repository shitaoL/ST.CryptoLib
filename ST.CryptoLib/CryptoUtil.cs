using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace ST.CryptoLib
{
    public class CryptoUtil
    {
        private static readonly byte[] _IV = { 0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF };
        private static readonly string _secretKey = "#shitao@";
        private static readonly string _keyContainerName = "rsa_shitao";
        private static readonly Encoding _defaultEncoding = Encoding.UTF8;

        public static string MD5Hash(string input, Encoding encoding = null)
        {
            if (encoding == null) { encoding = _defaultEncoding; }
            MD5 md5 = MD5.Create();
            byte[] bt = md5.ComputeHash(encoding.GetBytes(input));
            return Convert.ToBase64String(bt);
        }
        public static bool MD5Verify(string input, string hashValue, Encoding encoding = null)
        {
            return hashValue != null && MD5Hash(input, encoding) == hashValue;
        }

        public static string SHA1Hash(string input, Encoding encoding = null)
        {
            if (encoding == null) { encoding = _defaultEncoding; }
            SHA1 sha1 = SHA1.Create();
            byte[] bt = sha1.ComputeHash(encoding.GetBytes(input));
            return Convert.ToBase64String(bt);
        }
        public static bool SHA1Verify(string input, string hashValue, Encoding encoding = null)
        {
            return hashValue != null && SHA1Hash(input, encoding) == hashValue;
        }

        public static string SHA256Hash(string input, Encoding encoding = null)
        {
            if (encoding == null) { encoding = _defaultEncoding; }
            SHA256 sha256 = SHA256.Create();
            byte[] bt = sha256.ComputeHash(encoding.GetBytes(input));
            return Convert.ToBase64String(bt);
        }
        public static bool SHA256Verify(string input, string hashValue, Encoding encoding = null)
        {
            return hashValue != null && SHA256Hash(input, encoding) == hashValue;
        }

        public static string SHA384Hash(string input, Encoding encoding = null)
        {
            if (encoding == null) { encoding = _defaultEncoding; }
            SHA384 sha384 = SHA384.Create();
            byte[] bt = sha384.ComputeHash(encoding.GetBytes(input));
            return Convert.ToBase64String(bt);
        }
        public static bool SHA384Verify(string input, string hashValue, Encoding encoding = null)
        {
            return hashValue != null && SHA384Hash(input, encoding) == hashValue;
        }

        public static string SHA512Hash(string input, Encoding encoding = null)
        {
            if (encoding == null) { encoding = _defaultEncoding; }
            SHA512 sha512 = SHA512.Create();
            byte[] bt = sha512.ComputeHash(encoding.GetBytes(input));
            return Convert.ToBase64String(bt);
        }
        public static bool SHA512Verify(string input, string hashValue, Encoding encoding = null)
        {
            return hashValue != null && SHA512Hash(input, encoding) == hashValue;
        }

        public static string DESEncrypt(string input, string secretKey = null, Encoding encoding = null)
        {
            if (string.IsNullOrEmpty(secretKey)) { secretKey = _secretKey; }
            if (secretKey.Length != 8) { throw new ArgumentException("The parameter secretKey length must be 8 bits."); }
            if (encoding == null) { encoding = _defaultEncoding; }
            byte[] bt = encoding.GetBytes(input);
            using (MemoryStream ms = new MemoryStream())
            using (DESCryptoServiceProvider des = new DESCryptoServiceProvider())
            using (CryptoStream cs = new CryptoStream(ms, des.CreateEncryptor(encoding.GetBytes(secretKey), _IV), CryptoStreamMode.Write))
            {
                cs.Write(bt, 0, bt.Length);
                cs.FlushFinalBlock();
                return Convert.ToBase64String(ms.ToArray());
            }
        }
        public static string DESDecrypt(string input, string secretKey = null, Encoding encoding = null)
        {
            if (string.IsNullOrEmpty(secretKey)) { secretKey = _secretKey; }
            if (secretKey.Length != 8) { throw new ArgumentException("The parameter secretKey length must be 8 bits."); }
            if (encoding == null) { encoding = _defaultEncoding; }
            byte[] bt = Convert.FromBase64String(input);
            using (MemoryStream ms = new MemoryStream())
            using (DESCryptoServiceProvider des = new DESCryptoServiceProvider())
            using (CryptoStream cs = new CryptoStream(ms, des.CreateDecryptor(encoding.GetBytes(secretKey), _IV), CryptoStreamMode.Write))
            {
                cs.Write(bt, 0, bt.Length);
                cs.FlushFinalBlock();
                return encoding.GetString(ms.ToArray());
            }
        }

        public static string RSAEncrypt(string input, Encoding encoding = null)
        {
            if (encoding == null) { encoding = _defaultEncoding; }
            CspParameters param = new CspParameters();
            param.KeyContainerName = _keyContainerName;//key container name, must be match decrypt's key container name
            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(param))
            {
                byte[] bt = encoding.GetBytes(input);
                bt = rsa.Encrypt(bt, false);
                return Convert.ToBase64String(bt);
            }
        }
        public static string RSADecrypt(string ciphertext, Encoding encoding = null)
        {
            if (encoding == null) { encoding = _defaultEncoding; }
            CspParameters param = new CspParameters();
            param.KeyContainerName = _keyContainerName; //key container name, must be match encrypt's key container name
            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(param))
            {
                byte[] bt = Convert.FromBase64String(ciphertext);
                bt = rsa.Decrypt(bt, false);
                return encoding.GetString(bt);
            }
        }

    }
}
