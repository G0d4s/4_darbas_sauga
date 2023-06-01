package org.example;

import java.io.DataInputStream;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.security.KeyFactory;

public class Main {

    public static void main(String[] args) {
        try {
            // Same address and port as senders
            String ipAddress = "127.0.0.1";
            int port = 2002;

            try (ServerSocket receiver = new ServerSocket(port)) {
                System.out.println("Waiting for connection...");

                try (Socket client = receiver.accept();
                     DataInputStream inputStream = new DataInputStream(client.getInputStream())) {

                    System.out.println("Connected!");

                    byte[] buffer = new byte[1024];

                    byte[] message = null;
                    byte[] signature = null;

                    // Receive public key
                    byte[] publicKeyLengthBytes = new byte[4];
                    inputStream.read(publicKeyLengthBytes);

                    int publicKeyLength = bytesToInt(publicKeyLengthBytes);
                    byte[] publicKeyBytes = new byte[publicKeyLength];

                    inputStream.read(publicKeyBytes);
                    System.out.println("Received public key.");

                    // Receive message
                    byte[] messageLengthBytes = new byte[4];
                    inputStream.read(messageLengthBytes);

                    int messageLength = bytesToInt(messageLengthBytes);
                    message = new byte[messageLength];

                    inputStream.read(message);
                    System.out.println("Received message.");

                    // Receive signature
                    byte[] signatureLengthBytes = new byte[4];
                    inputStream.read(signatureLengthBytes);

                    int signatureLength = bytesToInt(signatureLengthBytes);
                    signature = new byte[signatureLength];

                    inputStream.read(signature);
                    System.out.println("Received signature.");

                    // Convert public key bytes to PublicKey object
                    X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
                    PublicKey publicKey = KeyFactory.getInstance("RSA").generatePublic(keySpec);

                    // Verify the digital signature using the received public key
                    Signature rsaPublic = Signature.getInstance("SHA256withRSA");
                    rsaPublic.initVerify(publicKey);
                    rsaPublic.update(message);

                    System.out.println("Received message: " + new String(message, StandardCharsets.UTF_8));
                    System.out.println("Received signature: " + Arrays.toString(signature));

                    boolean isVerified = rsaPublic.verify(signature);

                    String verificationResult = isVerified ? "Digital signature is verified." : "Digital signature is not verified.";
                    System.out.println(verificationResult);
                }
            }

        } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException | InvalidKeyException | SignatureException e) {
            e.printStackTrace();
        }
    }

    private static int bytesToInt(byte[] bytes) {
        return (bytes[0] & 0xFF) << 24 | (bytes[1] & 0xFF) << 16 | (bytes[2] & 0xFF) << 8 | (bytes[3] & 0xFF);
    }
}