package com.company;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public class Cifrar {

    // 1.1.i
    public static KeyPair randomGenerate(int len) {
        KeyPair keys = null;
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(len);
            keys = keyGen.genKeyPair();
        } catch (Exception ex) {
            System.err.println("Generador no disponible.");
        }
        return keys;
    }

    public static byte[] encryptData(byte[] data, PublicKey pub) {
        byte[] encryptedData = null;
        try {
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding","SunJCE");
            cipher.init(Cipher.ENCRYPT_MODE, pub);
            encryptedData =  cipher.doFinal(data);
        } catch (Exception  ex) {
            System.err.println("Error xifrant: " + ex);
        }
        return encryptedData;
    }

    public static byte[] decryptData(byte[] data, PrivateKey pub) {
        byte[] decryptData = null;
        try {
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding","SunJCE");
            cipher.init(Cipher.DECRYPT_MODE, pub);
            decryptData =  cipher.doFinal(data);
        } catch (Exception  ex) {
            System.err.println("Error desxifrant: " + ex);
        }
        return decryptData;
    }

    public static KeyStore loadKeyStore(String ksFile, String ksPwd) throws Exception {
        KeyStore ks = KeyStore.getInstance("JKS");
        File f = new File (ksFile);
        if (f.isFile()) {
            FileInputStream in = new FileInputStream (f);
            ks.load(in, ksPwd.toCharArray());
        }
        return ks;
    }

    public static SecretKey keygenKeyGeneration(int keySize) {
        SecretKey sKey = null;
        if ((keySize == 128) || (keySize == 192) || (keySize == 256)) {
            try {
                KeyGenerator kgen = KeyGenerator.getInstance("AES");
                kgen.init(keySize);
                sKey = kgen.generateKey();

            } catch (NoSuchAlgorithmException ex) {
                System.err.println("Generador no disponible");
            }
        }
        return sKey;
    }

    public static PublicKey getPublicKey(String fitxer) throws CertificateException, FileNotFoundException {
        FileInputStream fin = new FileInputStream(fitxer);
        CertificateFactory f = CertificateFactory.getInstance("X.509");
        X509Certificate certificate = (X509Certificate)f.generateCertificate(fin);
        PublicKey pk = certificate.getPublicKey();
        return pk;
    }

    // 4
    public static PublicKey getPublicKey(KeyStore ks, String alias, String pwMyKey) throws IOException, CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException {
        FileInputStream fin = new FileInputStream("D:\\Usuarios\\Aitor\\Documents\\DAM\\2 DAM\\M03 - Programació bàsica\\PROYECTOS\\A5\\src\\com\\company\\jordi.cer");
        CertificateFactory f = CertificateFactory.getInstance("X.509");
        X509Certificate certificate = (X509Certificate)f.generateCertificate(fin);
        PublicKey pk = certificate.getPublicKey();
        return pk;
    }

    // 5
    public static byte[] signData(byte[] data, PrivateKey priv) {
        byte[] signature = null;
        try {
            Signature signer = Signature.getInstance("SHA1withRSA");
            signer.initSign(priv);
            signer.update(data);
            signature = signer.sign();
        } catch (Exception ex) {
            System.err.println("Error signant les dades: " + ex);
        }
        return signature;
    }

    // 6
    public static boolean validateSignature(byte[] data, byte[] signature, PublicKey pub) {
        boolean isValid = false;
        try {
            Signature signer = Signature.getInstance("SHA1withRSA");
            signer.initVerify(pub);
            signer.update(data);
            isValid = signer.verify(signature);
        } catch (Exception ex) {
            System.err.println("Error validant les dades: " + ex);
        }
        return isValid;
    }
    // 2.2
    public static byte[][] encryptWrappedData(byte[] data, PublicKey pub) {
        byte[][] encWrappedData = new byte[2][];
        try {
            // Generamos la clave con el algoritmo AES
            KeyGenerator kgen = KeyGenerator.getInstance("AES");
            kgen.init(128);
            SecretKey sKey = kgen.generateKey();

            // Ciframos el mensaje a partir de la clave AES anterior
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, sKey);
            byte[] encMsg = cipher.doFinal(data);

            // Ciframos y envolvemos con el algoritmo de cifrado simetrico (RSA)
            cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.WRAP_MODE, pub);
            byte[] encKey = cipher.wrap(sKey);
            encWrappedData[0] = encMsg;
            encWrappedData[1] = encKey;

        } catch (Exception  ex) {
            System.err.println("Ha succeït un error xifrant: " + ex);
        }
        return encWrappedData;
    }

    public static byte[] decryptWrappedData(byte[][] data, PrivateKey priv) {
        byte[] msgDes = null;
        byte[] encMsg = data[0];
        try {
            // Desciframos y desenvolvemos con el algoritmo de cifrado simetrico (RSA)
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.UNWRAP_MODE, priv);
            Key decKey = cipher.unwrap(data[1],"AES",Cipher.SECRET_KEY);

            // Desciframos el mensaje con el algoritmo AES
            cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE,decKey);
            msgDes = cipher.doFinal(encMsg);

        } catch (Exception  ex) {
        System.err.println("Ha succeït un error desxifrant: " + ex);
    }
        return msgDes;
    }
}