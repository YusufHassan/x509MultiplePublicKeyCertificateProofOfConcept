package x509certificates;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.digests.SHA512tDigest;
import org.bouncycastle.pqc.crypto.sphincs.SPHINCS256KeyGenerationParameters;
import org.bouncycastle.pqc.crypto.sphincs.SPHINCS256KeyPairGenerator;
import org.bouncycastle.pqc.crypto.sphincs.SPHINCSPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.sphincs.SPHINCSPublicKeyParameters;

public class X509MultipleKeyCertificateFileUtil {

	public static void writeBytesToFile(byte[] bytes, File file) throws IOException {
        FileOutputStream outputStream = new FileOutputStream(file);
        outputStream.write(bytes);
        outputStream.close();
	}
	
	public static void writeSphincsKeysToFile() throws IOException {
		SPHINCS256KeyPairGenerator generator = new SPHINCS256KeyPairGenerator();
	    generator.init(new SPHINCS256KeyGenerationParameters(new SecureRandom(), new SHA512tDigest(256)));
	    AsymmetricCipherKeyPair keyPair = generator.generateKeyPair();
	    SPHINCSPublicKeyParameters caPublicKey = (SPHINCSPublicKeyParameters) keyPair.getPublic();
	    SPHINCSPrivateKeyParameters caPrivateKey = (SPHINCSPrivateKeyParameters) keyPair.getPrivate();
	    writeBytesToFile(caPublicKey.getKeyData(), new File("sphincsCaPublicKey"));
	    writeBytesToFile(caPrivateKey.getKeyData(), new File("sphincsCaPrivateKey"));
	}
	public static void writeRSA() throws NoSuchAlgorithmException {
		KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA");
		kpGen.initialize(2048);
		KeyPair keyPair = kpGen.generateKeyPair();
		PublicKey RSAPubKey = keyPair.getPublic();
		PrivateKey RSAprivKey = keyPair.getPrivate();
		writeObjectToFile(RSAPubKey, new File("rsaCaPublicKey"));
		writeObjectToFile(RSAprivKey, new File("rsaCaPrivateKey"));
	}
	public static void writeObjectToFile(Object serObj, File file) {
        try {
            FileOutputStream fileOutputStream = new FileOutputStream(file);
            ObjectOutputStream objectOutputStream = new ObjectOutputStream(fileOutputStream);
            objectOutputStream.writeObject(serObj);
            objectOutputStream.close();
            System.out.println("The Object was succesfully written to a file");
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }
	public static void main(String[] args) {

	}

}
