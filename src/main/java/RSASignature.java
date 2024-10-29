import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.SecureRandom;

public class RSASignature {
    private BigInteger n, d, e;

    private int bitLength = 1024; // Bit length for the prime numbers

    // Constructor to generate keys
    public RSASignature() {
        generateKeys();
    }

    // Method to generate the public and private key pair
    public void generateKeys() {
        SecureRandom random = new SecureRandom();

        // Generate two large prime numbers
        BigInteger p = BigInteger.probablePrime(bitLength / 2, random);
        BigInteger q = BigInteger.probablePrime(bitLength / 2, random);

        n = p.multiply(q); // Calculate n = p * q
        BigInteger phi = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE)); // Euler's totient function φ(n) = (p-1)(q-1)

        // Choose an integer e such that 1 < e < phi and gcd(e, phi) = 1
        e = new BigInteger("65537"); // Commonly used prime exponent

        // Calculate d as the modular multiplicative inverse of e modulo φ(n)
        d = e.modInverse(phi);
    }

    // Method to sign a message with the private key
    public BigInteger signMessage(String message) throws Exception {
        // Generate message hash using SHA-256
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] hash = md.digest(message.getBytes());

        // Convert the hash to BigInteger and sign it by raising it to the power of d modulo n
        return new BigInteger(1, hash).modPow(d, n);
    }

    // Method to verify a signature with the public key
    public boolean verifySignature(String message, BigInteger signature) throws Exception {
        // Generate the message hash using SHA-256
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] hash = md.digest(message.getBytes());
        BigInteger hashBigInt = new BigInteger(1, hash);

        // Decrypt the signature with the public key to get the original hash
        BigInteger decryptedHash = signature.modPow(e, n);

        // Check if the decrypted hash matches the hash of the message
        return hashBigInt.equals(decryptedHash);
    }

    // Getters for public key components
    public BigInteger getN() {
        return n;
    }

    public BigInteger getE() {
        return e;
    }
}
