import java.math.BigInteger;

public class Main {
    public static void main(String[] args) {
        try {
            // Instantiate RSASignature class to generate keys
            RSASignature rsaSignature = new RSASignature();

            // Display the generated public key
            System.out.println("Public Key (n, e): (" + rsaSignature.getN() + ", " + rsaSignature.getE() + ")");

            // Message to be signed
            String message = "This is a test message for RSA digital signature.";

            // Sign the message using the private key
            BigInteger signature = rsaSignature.signMessage(message);
            System.out.println("Digital Signature: " + signature);

            // Verify the signature using the public key
            boolean isValid = rsaSignature.verifySignature(message, signature);
            System.out.println("Signature valid: " + isValid);

            // Change the message to see the verification fail
            String modifiedMessage = "This is a modified message.";
            boolean isModifiedValid = rsaSignature.verifySignature(modifiedMessage, signature);
            System.out.println("Modified message signature valid: " + isModifiedValid);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
