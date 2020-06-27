using System;
using System.Security.Cryptography;
using System.Text;

namespace JwtReader.ConsoleApp
{
    //https://stackoverflow.com/questions/34403823/verifying-jwt-signed-with-the-rs256-algorithm-using-public-key-in-c-sharp
    class Program
    {
        static void Main(string[] args) 
        {
            Console.WriteLine("Hello World!");

            //FromStackoverflow();
            var tokenStr = "eyJhbGciOiJSUzI1NiIsImtpZCI6IkJENTVCQ0RGRDdEQzQzQTZCQUNENDI2RTZFQzFFMThBRUMzQ0UzNzVSUzI1NiIsInR5cCI6ImF0K2p3dCIsIng1dCI6InZWVzgzOWZjUTZhNnpVSnVic0hoaXV3ODQzVSJ9.eyJuYmYiOjE1OTE0ODUyMjYsImV4cCI6MTU5MTQ4ODgyNiwiaXNzIjoiaHR0cHM6Ly9sb2NhbGhvc3Q6NTAwMSIsImF1ZCI6WyJyZXNvdXJjZTEiLCJyZXNvdXJjZTIiXSwiY2xpZW50X2lkIjoiY2xpZW50IiwianRpIjoiMzdCOUZBNjYzODYwOEJFNEVDRUQwMjdGREM3QzgwM0YiLCJpYXQiOjE1OTE0ODUyMjYsInNjb3BlIjpbIklkZW50aXR5U2VydmVyQXBpIiwicmVzb3VyY2UxLnNjb3BlMSIsInJlc291cmNlMi5zY29wZTEiXX0.DYKIJ8Ns0GvbPIDz4_PCg5Q9usKABUX2fKtiJUo06RyNkVpKa2K6rnW929PPwfkEyuTpmR91cB-L392EYBX-UpsksOm7xKp3JwvkObrDXupg2zZGVm7l0abSDpfBhS9HaxQ0xtwBdbkeM8MEo_bZHS9TyQvbwdsxLLAXiT9Ba9nEAdg4LdE5a_HtCZc3uHNHKwzj4qAKWhevxNCh9VpyTe5fFPOe6Mx2SkFJ6thFZoXE5TUyvzjT69BpwGL4vjPYULFJvGq4ReiUvdWhBJzH4rBuSMrPuUA2tFYITEZ6g2iq21oE1yAQ9tNPCIcFikJ0CzjOt0LfVkzczPX8NqaVqg";
            var modulus = "4BHPb4kNFadWsFfvOhAubS4GUsMogvBBpugquY0vlRlX9qYvA_LmkmoY5YCkHQtDipsxnh2O60q19lhWWCFfJ8VLLoUnnuQsrfXwba8rXtGukxOvqkslrUf4HXEEh6xElVF0mYxJ6lHxuZpMpWXm0s2cZ6jebMw2iWrlI3rbPe1at5F6OEEwKNcY6ORmIRI_rusJdMzmKQvbdhqhhsi6ckf0nVKq7h-Zs0ZWDcTwKsjYQDoE4nQ-ohwgKPzlIE8FZGbrqUPJ9ueVJRXVXT3HZ0L50GO1ZoDduONLW9FxTWWUucMOuDjZOXUnEOYdhmbH5F2X7pkn-aQ21un41bnnkw";
            var exponent = "AQAB";
            VerifyJwt(tokenStr, modulus, exponent);

        }
        static void FromStackoverflow()
        {
            string tokenStr = "eyJraWQiOiIxZTlnZGs3IiwiYWxnIjoiUlMyNTYifQ.ewogImlzcyI6ICJodHRwOi8vc2VydmVyLmV4YW1wbGUuY29tIiwKICJzdWIiOiAiMjQ4Mjg5NzYxMDAxIiwKICJhdWQiOiAiczZCaGRSa3F0MyIsCiAibm9uY2UiOiAibi0wUzZfV3pBMk1qIiwKICJleHAiOiAxMzExMjgxOTcwLAogImlhdCI6IDEzMTEyODA5NzAsCiAiY19oYXNoIjogIkxEa3RLZG9RYWszUGswY25YeENsdEEiCn0.XW6uhdrkBgcGx6zVIrCiROpWURs-4goO1sKA4m9jhJIImiGg5muPUcNegx6sSv43c5DSn37sxCRrDZZm4ZPBKKgtYASMcE20SDgvYJdJS0cyuFw7Ijp_7WnIjcrl6B5cmoM6ylCvsLMwkoQAxVublMwH10oAxjzD6NEFsu9nipkszWhsPePf_rM4eMpkmCbTzume-fzZIi5VjdWGGEmzTg32h3jiex-r5WTHbj-u5HL7u_KP3rmbdYNzlzd1xWRYTUs4E8nOTgzAUwvwXkIQhOh5TPcSMBYy6X3E7-_gr9Ue6n4ND7hTFhtjYs3cjNKIA08qm5cpVYFMFMG6PkhzLQ";
            string[] tokenParts = tokenStr.Split('.');

            var modulus = "w7Zdfmece8iaB0kiTY8pCtiBtzbptJmP28nSWwtdjRu0f2GFpajvWE4VhfJAjEsOcwYzay7XGN0b-X84BfC8hmCTOj2b2eHT7NsZegFPKRUQzJ9wW8ipn_aDJWMGDuB1XyqT1E7DYqjUCEOD1b4FLpy_xPn6oV_TYOfQ9fZdbE5HGxJUzekuGcOKqOQ8M7wfYHhHHLxGpQVgL0apWuP2gDDOdTtpuld4D2LK1MZK99s9gaSjRHE8JDb1Z4IGhEcEyzkxswVdPndUWzfvWBBWXWxtSUvQGBRkuy1BHOa4sP6FKjWEeeF7gm7UMs2Nm2QUgNZw6xvEDGaLk4KASdIxRQ";
            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
            rsa.ImportParameters(new RSAParameters()
            {
                Modulus = FromBase64Url("w7Zdfmece8iaB0kiTY8pCtiBtzbptJmP28nSWwtdjRu0f2GFpajvWE4VhfJAjEsOcwYzay7XGN0b-X84BfC8hmCTOj2b2eHT7NsZegFPKRUQzJ9wW8ipn_aDJWMGDuB1XyqT1E7DYqjUCEOD1b4FLpy_xPn6oV_TYOfQ9fZdbE5HGxJUzekuGcOKqOQ8M7wfYHhHHLxGpQVgL0apWuP2gDDOdTtpuld4D2LK1MZK99s9gaSjRHE8JDb1Z4IGhEcEyzkxswVdPndUWzfvWBBWXWxtSUvQGBRkuy1BHOa4sP6FKjWEeeF7gm7UMs2Nm2QUgNZw6xvEDGaLk4KASdIxRQ"),
                Exponent = FromBase64Url("AQAB")
            });

            SHA256 sha256 = SHA256.Create();
            byte[] hash = sha256.ComputeHash(Encoding.UTF8.GetBytes(tokenParts[0] + '.' + tokenParts[1]));

            RSAPKCS1SignatureDeformatter rsaDeformatter = new RSAPKCS1SignatureDeformatter(rsa);
            rsaDeformatter.SetHashAlgorithm("SHA256");
            if (rsaDeformatter.VerifySignature(hash, FromBase64Url(tokenParts[2])))
                Console.WriteLine("Signature is verified");
        }


        static byte[] FromBase64Url(string base64Url)
        {
            string padded = base64Url.Length % 4 == 0
                ? base64Url : base64Url + "====".Substring(base64Url.Length % 4);
            string base64 = padded.Replace("_", "/")
                                  .Replace("-", "+");
            return Convert.FromBase64String(base64);
        }

        public static void VerifyJwt(string token, string publicKeyJwkN, string publicKeyJwkE)
        {
            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
            {
                var authToken = new AuthToken(token);
                rsa.ImportParameters(new RSAParameters()
                {
                    Modulus = FromBase64Url(publicKeyJwkN),
                    Exponent = FromBase64Url(publicKeyJwkE)
                });
                var sha256 = SHA256.Create();
                var hash = sha256.ComputeHash(Encoding.UTF8.GetBytes(authToken.Header + '.' + authToken.PayLoad));

                var rsaDeformatter = new RSAPKCS1SignatureDeformatter(rsa);
                rsaDeformatter.SetHashAlgorithm("SHA256");
                if (rsaDeformatter.VerifySignature(hash, FromBase64Url(authToken.Signature)))
                    Console.WriteLine("Signature is verified");
            }
        }


        //https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.rsapkcs1signaturedeformatter.verifysignature?view=netcore-3.1
        static void Main1()
        {
            try
            {
                //Create a new instance of RSACryptoServiceProvider.
                using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
                {
                    //The hash to sign.
                    byte[] hash;
                    using (SHA256 sha256 = SHA256.Create())
                    {
                        byte[] data = new byte[] { 59, 4, 248, 102, 77, 97, 142, 201, 210, 12, 224, 93, 25, 41, 100, 197, 213, 134, 130, 135 };
                        hash = sha256.ComputeHash(data);
                    }

                    //Create an RSASignatureFormatter object and pass it the 
                    //RSACryptoServiceProvider to transfer the key information.
                    RSAPKCS1SignatureFormatter RSAFormatter = new RSAPKCS1SignatureFormatter(rsa);

                    //Set the hash algorithm to SHA256.
                    RSAFormatter.SetHashAlgorithm("SHA256");

                    //Create a signature for HashValue and return it.
                    byte[] signedHash = RSAFormatter.CreateSignature(hash);
                    //Create an RSAPKCS1SignatureDeformatter object and pass it the  
                    //RSACryptoServiceProvider to transfer the key information.
                    RSAPKCS1SignatureDeformatter RSADeformatter = new RSAPKCS1SignatureDeformatter(rsa);
                    RSADeformatter.SetHashAlgorithm("SHA256");
                    //Verify the hash and display the results to the console. 
                    if (RSADeformatter.VerifySignature(hash, signedHash))
                    {
                        Console.WriteLine("The signature was verified.");
                    }
                    else
                    {
                        Console.WriteLine("The signature was not verified.");
                    }
                }
            }
            catch (CryptographicException e)
            {
                Console.WriteLine(e.Message);
            }
        }
    }

    public class AuthToken
    {
        public AuthToken(string token)
        {
            string[] tokenParts = token.Split('.');
            Header = tokenParts[0];
            PayLoad = tokenParts[1];
            Signature = tokenParts[2];
        }

        public string Header { get; private set; }
        public string PayLoad { get; private set; }
        public string Signature { get; private set; }
    }
}
