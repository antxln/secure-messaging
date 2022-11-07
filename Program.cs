/*
Use Public Key Encryption RSA to securely communicate with others on a server.
*/
using System;
using System.IO;
using System.Numerics;
using System.Collections.Generic;
using System.Net.Http;
using prime_gen;
using System.Security.Cryptography;
using System.Linq;
using Newtonsoft.Json;
using System.Text;
using System.Threading.Tasks;

namespace Messenger
{
    /*
    Public key class standard
    */
    internal class Public_Key
    {
        public string email { get; set; }
        public string key { get; set; }
    }

    /*
    Private key class standard
    */
    internal class Private_Key
    {
        public List<string> email { get; set; }
        public string key { get; set; }
    }

    /*
    Message class standard
    */
    internal class Message
    {
        public string email { get; set; }
        public string content { get; set; }
    }

    /*
    Class for Secure Messenger application
    */
    class Messenger {
        private const int PRIME_E = 65537;
        private const string PUBLIC_PATH = "public.key";
        private const string PRIVATE_PATH = "private.key";
        private const string KEY_FILE_FORMAT = "{0}.key";
        private const string KEY_URL_FORMAT = "http://HIDDEN:5000/Key/{0}";
        private const string MSG_URL_FORMAT = "http://HIDDEN:5000/Message/{0}";
        private readonly HttpClient client = new HttpClient();

        /*
        Determine the inverse of a mod n

        a: value to find inverse of
        n: mod value
        */
        static BigInteger modInverse(BigInteger a, BigInteger n) {
            BigInteger i = n, v = 0, d = 1;
            while (a > 0) {
                BigInteger t = i/a, x = a;
                a = i % x;
                i = x;
                x = d;
                d = v - t * x;
                v = x;
            }
            v %= n;
            if (v < 0) v = (v + n) % n;
            return v;
        }

        /*
        Generate a public and private key pair of keysize bits
        and store the keys locally
        */
        public void keyGen(int keysize) {
            var offset = RandomNumberGenerator.GetInt32(keysize / 10 / 8 + 1) * 8;
            int p_size = keysize / 2 - offset, q_size = keysize / 2 + offset;

            var pg = new PrimeGen();
            BigInteger p = pg.run(p_size), q = pg.run(q_size), e = PRIME_E;
            if (p == 0 || q == 0) {
                Console.WriteLine("Number of bits for p and q must be divisible by 8");
                return;
            }
            BigInteger n = p * q, r = (p - 1) * (q - 1);
            var d = modInverse(e, r);

            byte[] E = e.ToByteArray(), D = d.ToByteArray(), N = n.ToByteArray();
            byte[] e_size = BitConverter.GetBytes(E.Length), d_size = BitConverter.GetBytes(D.Length), n_size = BitConverter.GetBytes(N.Length);

            var private_key = d_size.Concat(D).Concat(n_size).Concat(N).ToArray();
            var pri_k = new Private_Key {
                email = new List<string>(),
                key = Convert.ToBase64String(private_key)
            };
            string json = JsonConvert.SerializeObject(pri_k, Formatting.Indented);
            File.WriteAllText(PRIVATE_PATH, json);

            if (BitConverter.IsLittleEndian) {
                Array.Reverse(e_size);
                Array.Reverse(n_size);
            }
            var public_key = e_size.Concat(E).Concat(n_size).Concat(N).ToArray();
            var pub_k = new Public_Key {
                email = "",
                key = Convert.ToBase64String(public_key)
            };
            json = JsonConvert.SerializeObject(pub_k, Formatting.Indented);
            File.WriteAllText(PUBLIC_PATH, json);
        }

        /*
        Send the local public key to the server, associated with email
        */
        public async Task sendKeyAsync(string email) {
            if (!File.Exists(PUBLIC_PATH)) {
                Console.WriteLine("key does not exist. Generate with keyGen <keysize>");
                return;
            }

            var json = File.ReadAllText(PUBLIC_PATH);
            var pub_key = JsonConvert.DeserializeObject<Public_Key>(json);
            pub_key.email = email;
            json = JsonConvert.SerializeObject(pub_key, Formatting.Indented);
            File.WriteAllText(PUBLIC_PATH, json);

            var url = String.Format(KEY_URL_FORMAT, email);
            var content = new StringContent(json, Encoding.UTF8, "application/json");
            try	{
                HttpResponseMessage response = await client.PutAsync(url, content);
                response.EnsureSuccessStatusCode();
                Console.WriteLine("Key saved");
            } catch (HttpRequestException) {
                Console.WriteLine("Unable to sendKey to server.");
                return;
            }

            json = File.ReadAllText(PRIVATE_PATH);
            var pri_key = JsonConvert.DeserializeObject<Private_Key>(json);
            if (!pri_key.email.Contains(email)) pri_key.email.Add(email);
            json = JsonConvert.SerializeObject(pri_key, Formatting.Indented);
            File.WriteAllText(PRIVATE_PATH, json);
        }

        /*
        Get key attached to email from server and save locally
        */
        public async Task getKeyAsync(string email) {
            var path = String.Format(KEY_FILE_FORMAT, email);
            var url = String.Format(KEY_URL_FORMAT, email);
            try	{
                var responseBody = await client.GetStringAsync(url);
                File.WriteAllText(path, responseBody);
            } catch (HttpRequestException) {
                Console.WriteLine("Unable to getKey from server.");
                return;
            }
        }

        /*
        Send an encoded message, plaintext, to user using public key attached to email
        */
        public async Task sendMsgAsync(string email, string plaintext) {
            var path = String.Format(KEY_FILE_FORMAT, email);
            if (!File.Exists(path)) {
                Console.WriteLine($"Key does not exist for {email}");
                return;
            }
            var json = File.ReadAllText(path);
            var pub_key = JsonConvert.DeserializeObject<Public_Key>(json);
            var key = pub_key.key;
            var bytes = Convert.FromBase64String(key);

            var i = 0;
            var j = 4;
            var e_bytes = bytes[..j];
            if (BitConverter.IsLittleEndian) Array.Reverse(e_bytes);
            i = j;
            j += BitConverter.ToInt32(e_bytes);
            var E_bytes = bytes[i..j];
            var E = new BigInteger(E_bytes);

            i = j;
            j += 4;
            var n_bytes = bytes[i..j];
            if (BitConverter.IsLittleEndian) Array.Reverse(n_bytes);
            i = j;
            j += BitConverter.ToInt32(n_bytes);
            var N_bytes = bytes[i..];
            var N = new BigInteger(N_bytes);

            var plain_bytes = Encoding.ASCII.GetBytes(plaintext);
            var plain = new BigInteger(plain_bytes);
            var cipher = BigInteger.ModPow(plain, E, N);
            var cipher_bytes = cipher.ToByteArray();
            var ciphertext = Convert.ToBase64String(cipher_bytes);
            
            var msg = new Message {
                email = email,
                content = ciphertext
            };
            json = JsonConvert.SerializeObject(msg, Formatting.Indented);

            var url = String.Format(MSG_URL_FORMAT, email);
            var content = new StringContent(json, Encoding.UTF8, "application/json");
            try	{
                HttpResponseMessage response = await client.PutAsync(url, content);
                response.EnsureSuccessStatusCode();
                Console.WriteLine("Message written");
            } catch (HttpRequestException) {
                Console.WriteLine("Unable to sendMsg");
                return;
            }
        }

        /*
        Get encrypted message from emails mailbox and print plaintext if able to decode
        */
        public async Task getMsgAsync(string email) {
            if (!File.Exists(PRIVATE_PATH)) {
                Console.WriteLine($"key does not exist. Generate with keyGen <keysize>");
                return;
            }
            
            var json = File.ReadAllText(PRIVATE_PATH);
            var pri_key = JsonConvert.DeserializeObject<Private_Key>(json);
            if (!pri_key.email.Contains(email)) {
                Console.WriteLine("Message cannot be decoded.");
                return;
            }

            var url = String.Format(MSG_URL_FORMAT, email);
            string responseBody;
            try	{
                responseBody = await client.GetStringAsync(url);
            } catch (HttpRequestException) {
                Console.WriteLine("Unable to getMsg from server.");
                return;
            }

            var msg = JsonConvert.DeserializeObject<Message>(responseBody);
            var key = pri_key.key;
            var bytes = Convert.FromBase64String(key);

            var i = 0;
            var j = 4;
            var d_bytes = bytes[..j];
            i = j;
            j += BitConverter.ToInt32(d_bytes);
            var D_bytes = bytes[i..j];
            var D = new BigInteger(D_bytes);

            i = j;
            j += 4;
            var n_bytes = bytes[i..j];
            i = j;
            j += BitConverter.ToInt32(n_bytes);
            var N_bytes = bytes[i..];
            var N = new BigInteger(N_bytes);

            var cipher_bytes = Convert.FromBase64String(msg.content);
            var cipher = new BigInteger(cipher_bytes);
            var plain = BigInteger.ModPow(cipher, D, N);
            var plain_bytes = plain.ToByteArray();
            var plaintext = Encoding.ASCII.GetString(plain_bytes);
            Console.WriteLine(plaintext);
        }
    }

    /*
    Entry class for this program
    */
    class Program
    {
        private static Dictionary<string, string> OPTIONS = new Dictionary<string, string>{
            {"keyGen", "<keysize> - generate a keypair (public and private keys) and store them locally (in files called public.key and private.key respectively), as base64 encoded keys. Note, it is NOT associated with an email address until it is sent to the server."},
            {"sendKey", "<email> - send the public key to the server and register this email address as a valid receiver of messages. If the server already has a key for this user, it will be overwritten. SendKey also updates the local system to register the email address as valid (one for which messages can be decoded)."},
            {"getKey", "<email> - retrieve a base64 encoded public key for a particular user."},
            {"sendMsg", "<email> <plaintext> - base64 encode a message for a user in the to field."},
            {"getMsg", "<email> - retrieve the base64 encoded message for a particular user and decode if possible."}
        };

        private static void help_option(string option) {
            var msg = "foobar";
            var success = OPTIONS.TryGetValue(option, out msg);
            if (success) Console.WriteLine($"{option} {msg}");
            else Console.WriteLine($"{option} not valid");
        }

        private static void help() {
            Console.WriteLine("Usage: dotnet run <option> <other arguments>\n");
            Console.WriteLine("Options:");
            foreach (KeyValuePair<string, string> kvp in OPTIONS) {
                Console.WriteLine($"{kvp.Key} {kvp.Value}");
            }
        }

        /*
        Entry for program. Run prime gen based on arguments.
        */
        static async Task Main(string[] args) {
            if (args.Length < 1) {
                help();
            } else {
                var app = new Messenger();
                var option = args[0];
                switch (option) {
                    case "keyGen":
                        if (args.Length == 2) {
                            var keysize = 0;
                            var success = Int32.TryParse(args[1], out keysize);
                            if (success && keysize >= 0) app.keyGen(keysize);
                            else Console.WriteLine("keysize must be positive");
                        } else help_option(option);
                        break;
                    case "sendKey":
                        if (args.Length == 2) await app.sendKeyAsync(args[1]);
                        else help_option(option);
                        break;
                    case "getKey":
                        if (args.Length == 2) await app.getKeyAsync(args[1]);
                        else help_option(option);
                        break;
                    case "sendMsg":
                        if (args.Length == 3) await app.sendMsgAsync(args[1], args[2]);
                        else help_option(option);
                        break;
                    case "getMsg":
                        if (args.Length == 2) await app.getMsgAsync(args[1]);
                        else help_option(option);
                        break;
                    default:
                        help();
                        break;
                }
            }
        }
    }
}
