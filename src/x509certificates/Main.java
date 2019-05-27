package x509certificates;

public class Main {

	public static void main(String[] args) throws Exception {
		X509MultipleKeyCertificateFileUtil.writeRSA();
		X509MultipleKeyCertificateFileUtil.writeSphincsKeysToFile();
		X509CertificateGenerator generator = new X509CertificateGenerator();
		generator.generateX509Certificate("Sweden","Primekey","PKI","SecureCAMigration","SecureCAMigration","john.smith@gmail.com"
				,"http://www.somewebsite.com/ca.cer","http://ocsp.somewebsite.com");
		X509CertificateGenerator.testVerificationOfMultipleKeyCertificatesSPHINCS(2);
	}
}
