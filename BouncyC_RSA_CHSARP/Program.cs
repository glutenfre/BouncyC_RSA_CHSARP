using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;
using System.Threading.Tasks;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Math;

namespace BouncyC_RSA_CHSARP
{
    class Program
    {
        static BigInteger mod = new BigInteger("b259d2d6e627a768c94be36164c2d9fc79d97aab9253140e5bf17751197731d6f7540d2509e7b9ffee0a70a6e26d56e92d2edd7f85aba85600b69089f35f6bdbf3c298e05842535d9f064e6b0391cb7d306e0a2d20c4dfb4e7b49a9640bdea26c10ad69c3f05007ce2513cee44cfe01998e62b6c3637d3fc0391079b26ee36d5", 16);
        static BigInteger pubExp = new BigInteger("11", 16);
        static BigInteger privExp = new BigInteger("92e08f83cc9920746989ca5034dcb384a094fb9c5a6288fcc4304424ab8f56388f72652d8fafc65a4b9020896f2cde297080f2a540e7b7ce5af0b3446e1258d1dd7f245cf54124b4c6e17da21b90a0ebd22605e6f45c9f136d7a13eaac1c0f7487de8bd6d924972408ebb58af71e76fd7b012a8d0e165f3ae2e5077a8648e619", 16);

        static private void Encrypt()
        {
        string str;
        using (FileStream fs = new FileStream("plain.txt", FileMode.Open))
        {
            using (StreamReader sr = new StreamReader(fs))
            {
                str = sr.ReadToEnd();
            }
        }

            RsaKeyParameters pubParameters = new RsaKeyParameters(false, mod, pubExp);
            RsaBlindedEngine engine = new RsaBlindedEngine();
            engine.Init(true, pubParameters);
        
            byte[] data = Encoding.ASCII.GetBytes(str);
            byte[] encryptedData = engine.ProcessBlock(data, 0, data.Length);

        using (FileStream fsout = new FileStream("encoded.txt", FileMode.Create, FileAccess.Write))
        {
        using (BinaryWriter br = new BinaryWriter(fsout))
        {
        br.Write(encryptedData);
        }
        }
        }

        static private void Decrypt()
        {
        byte[] encryptedData;
        using (FileStream fs = new FileStream("encoded.txt", FileMode.Open))
        {
        using (BinaryReader br = new BinaryReader(fs))
        {
        encryptedData = br.ReadBytes((int)fs.Length);
        }
        }
            
            RsaKeyParameters privParameters = new RsaKeyParameters(true, mod, privExp);
            RsaBlindedEngine engine = new RsaBlindedEngine();
            engine.Init(false, privParameters);
            byte[] decryptedData = engine.ProcessBlock(encryptedData, 0, encryptedData.Length);

        using (FileStream fsout = new FileStream("decoded.txt", FileMode.Create, FileAccess.Write))
        {
        using (StreamWriter br = new StreamWriter(fsout))
        {
        br.Write(Encoding.ASCII.GetString(decryptedData));
        }
        }

        }

        static void Main(string[] args)
        {
            while (true)
            {
                int type = Int32.Parse(Console.ReadLine());
                if (type == 1)
                {
                    Encrypt();
                }
                if (type == 2)
                {
                    Decrypt();
                }
            }
        }
    }
}
