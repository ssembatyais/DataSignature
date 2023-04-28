using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.Remoting.Channels;

namespace ConsoleApp1
{
    internal class Program
    {
        static void Main(string[] args)
        {
            string data = "256789587888256789587888123789456FUTURELINK_TEST00C14BD32227/04/2023NoneHello Customer testing 1 2CASH";
            string digitalSignature = GetSignature(data);
            Console.WriteLine(digitalSignature);
            bool isValid = ValidSignature(data, digitalSignature);
            Console.WriteLine(isValid);

        }

        private static string GetSignature(string Tosign)
        {
            try
            {
                string certificate = @"E:\Certs\PBU\semaz.pfx";
                X509Certificate2 cert = new X509Certificate2(System.IO.File.ReadAllBytes(certificate)
                                          , "PostBank2019"
                                          , X509KeyStorageFlags.MachineKeySet |
                                            X509KeyStorageFlags.PersistKeySet |
                                            X509KeyStorageFlags.Exportable);
                RSACryptoServiceProvider rsa = (RSACryptoServiceProvider)cert.PrivateKey;

                // Hash the data
                SHA1Managed sha1 = new SHA1Managed();
                ASCIIEncoding encoding = new ASCIIEncoding();
                byte[] data = encoding.GetBytes(Tosign);
                byte[] hash = sha1.ComputeHash(data);

                // Sign the hash
                byte[] digitalCert = rsa.SignHash(hash, CryptoConfig.MapNameToOID("SHA1"));
                string strDigCert = Convert.ToBase64String(digitalCert);
                return strDigCert;
            }
            catch (Exception ee)
            {
                throw ee;
            }

        }

        public static bool ValidSignature(string text, string DigitalSignature)
        {
            bool IsValid = true;

            try
            {
                //string text = SchoolCode + StudentId + StudentName + Amount + PaymentType + PaymentDate + Channel + Username + Password;// trans.Narration + trans.SchoolCode + trans.Username + trans.Password;
                //string certPath = @"C:\PegPayCertificates1\PostBankPegPay\PostBankPegPay.cer";// dt2.Rows[0]["ValueVarriable"].ToString();
                string certPath = @"E:\PBU_TEST\certificate.crt";

                //string text = SchoolCode + StudentId + StudentName + Amount + TransactionID + PaymentType + PaymentDate + Channel + Username + Password;// trans.Narration + trans.SchoolCode + trans.Username + trans.Password;
                //string certPath = @"C:\StanbicCert\StanbicSchools.cer";// dt2.Rows[0]["ValueVarriable"].ToString();

                X509Certificate2 cert = new X509Certificate2(certPath);
                RSACryptoServiceProvider csp = (RSACryptoServiceProvider)cert.PublicKey.Key;
                SHA1Managed sha1 = new SHA1Managed();
                //UnicodeEncoding encoding = new UnicodeEncoding();
                ASCIIEncoding encoding = new ASCIIEncoding();
                byte[] data = encoding.GetBytes(text);
                byte[] hash = sha1.ComputeHash(data);
                byte[] sig = Convert.FromBase64String(DigitalSignature);
                bool valid = csp.VerifyHash(hash, CryptoConfig.MapNameToOID("SHA1"), sig);
                IsValid = valid;
            }
            catch (Exception ex)
            {
                return false;
            }

            return IsValid;
        }
    }
}
