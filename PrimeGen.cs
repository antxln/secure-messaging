/*
Generate large probably prime numbers
*/
using System;
using System.Diagnostics;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.Numerics;

namespace prime_gen
{
    /*
    Class for extension methods
    */
    public static class Extensions {

        /*
        Determine whether or not a value is probably prime, with a high amount
        of certainty (for 10 witnesses)

        value - value to judge
        witnesses - number of witnesses in algorithm
        */
        public static Boolean IsProbablyPrime(this BigInteger value,
                                                int witnesses = 10) {
            if (value <= 1) return false;

            if (witnesses <= 0) witnesses = 10;

            BigInteger d = value - 1;
            int s = 0;

            while (d % 2 == 0) {
                d /= 2;
                s += 1;
            }

            var size = value.ToByteArray().LongLength;

            var data_lock = new Object();
            var result = true;
            Parallel.For(0, witnesses, (i, state) => {
                var bytes = new byte[size];
                BigInteger a;
                do {
                    var Gen = new Random();
                    Gen.NextBytes(bytes);
                    a = new BigInteger(bytes);
                } while (a < 2 || a >= value - 2);

                BigInteger x = BigInteger.ModPow(a, d, value);
                if (!(x == 1 || x == value - 1)) {

                    for (int r = 1; r < s; r++) {
                        x = BigInteger.ModPow(x, 2, value);
                        if (x == 1) {
                            lock (data_lock) {
                                result = false;
                            }
                            state.Stop();
                            break;
                        }
                        if (x == value - 1) break;
                    }

                    if (x != value - 1) {
                        lock (data_lock) {
                            result = false;
                        }
                        state.Stop();
                    }
                }
            });
            return result;
        }
    }

    /*
    Class for prime number generation object
    */
    class PrimeGen {
        public static object data_lock = new Object();

        public BigInteger run(int bits) {
            BigInteger result = 0;
            if (bits < 0 || bits % 8 != 0) return result;
            var bites = bits / 8;
            Parallel.For(Int32.MinValue, Int32.MaxValue, (i, state) => {
                var rng = new RNGCryptoServiceProvider();
                var bytes = new byte[bites];
                rng.GetBytes(bytes);
                var bigint = BigInteger.Abs(new BigInteger(bytes));
                if (bigint.IsProbablyPrime()) {
                    lock (data_lock) {
                        if (result == 0) {
                            result = bigint;
                            state.Stop();
                        }
                    }
                }
            });
            return result;
        }
    }
}
