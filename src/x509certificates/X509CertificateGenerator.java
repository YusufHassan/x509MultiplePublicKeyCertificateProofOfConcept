package x509certificates;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Date;
import java.util.Random;

import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObjectParser;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERBoolean;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DERUTCTime;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA3Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.digests.SHA512tDigest;
import org.bouncycastle.pqc.crypto.MessageSigner;
import org.bouncycastle.pqc.crypto.newhope.NHKeyPairGenerator;
import org.bouncycastle.pqc.crypto.newhope.NHPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.newhope.NHPublicKeyParameters;
import org.bouncycastle.pqc.crypto.qtesla.QTESLAKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.qtesla.QTESLAKeyPairGenerator;
import org.bouncycastle.pqc.crypto.qtesla.QTESLAPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.qtesla.QTESLAPublicKeyParameters;
import org.bouncycastle.pqc.crypto.qtesla.QTESLASecurityCategory;
import org.bouncycastle.pqc.crypto.qtesla.QTESLASigner;
import org.bouncycastle.pqc.crypto.rainbow.RainbowKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.rainbow.RainbowKeyPairGenerator;
import org.bouncycastle.pqc.crypto.rainbow.RainbowParameters;
import org.bouncycastle.pqc.crypto.rainbow.RainbowPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.rainbow.RainbowPublicKeyParameters;
import org.bouncycastle.pqc.crypto.sphincs.SPHINCS256KeyGenerationParameters;
import org.bouncycastle.pqc.crypto.sphincs.SPHINCS256KeyPairGenerator;
import org.bouncycastle.pqc.crypto.sphincs.SPHINCS256Signer;
import org.bouncycastle.pqc.crypto.sphincs.SPHINCSPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.sphincs.SPHINCSPublicKeyParameters;
import org.bouncycastle.pqc.jcajce.spec.RainbowParameterSpec;
import org.bouncycastle.util.Arrays.Iterator;

public class X509CertificateGenerator {
	private static PublicKey rsaCaPublicKey = null;
	private static PrivateKey rsaCaPrivateKey = null;
	private static SPHINCSPrivateKeyParameters sphincsCaPrivateKey = null;
	private static SPHINCSPublicKeyParameters sphincsCaPublicKey = null;
    public static final String SIGNATURE_ALGORITHM_IDENTIFIER_OID = "1.2.840.113549.1.1.11";
	public static final String COUNTRY_NAME_OID = "2.5.4.6";
	public static final String ORGANIZATION_NAME_OID = "2.5.4.10";
	public static final String ORGANIZATIONAL_UNIT_NAME_OID = "2.5.4.11";
	public static final String ISSUER_COMMON_NAME = "2.5.4.3";
	public static final String SUBJECT_COMMON_NAME = "2.5.4.3";
	public static final String SUBJECT_KEY_IDENTIFIER = "2.5.29.14"; 
	public static final String AUTHORITY_KEY_IDENTIFIER = "2.5.29.35";
	public static final String BASIC_CONSTRAINTS_OID = "2.5.29.19";
	public static final String SUBJECT_ALTERNATIVE_NAME_OID = "2.5.29.17";
	public static final String CA_ISSUERS_OID = "1.3.6.1.5.5.7.48.2";
	public static final String OSCP_OID = "1.3.6.1.5.5.7.48.1";
    public static final String AUTHORITY_ACCESS_INFORMATION_OID = "1.3.6.1.5.5.7.1.1";
    public static final String ALTERNATIVE_SIGNATURE_VALUE_OID = "1.3.6.1.4.1.22408.1.1.4.3";
    public static final String ALTERNATIVE_ALGORITHM_IDENTIFIER_OID = "1.3.6.1.4.1.22408.1.1.4.4";
    public static final String ALTERNATIVE_ALGORITHM_IDENTIFIER_EXTENSION_OID = "1.3.6.1.4.1.22408.1.1.4.2";
    public static final String ALTERNTIVE_SUBJECT_KEY_INFO = "1.3.6.1.4.1.22408.1.1.4.1";
	
	
	
	
	private void readSphincsKeys() throws IOException {
		File altPubKeyFile = new File("sphincsCaPublicKey");
		FileInputStream fileInputStream = new FileInputStream(altPubKeyFile);
		byte[] bufferForAltPubKey = new byte[(int) altPubKeyFile.length()];
		fileInputStream.read(bufferForAltPubKey);
		sphincsCaPublicKey = new SPHINCSPublicKeyParameters(bufferForAltPubKey);
		fileInputStream.close();
		File altPrivKeyFile = new File("sphincsCaPrivateKey");
		fileInputStream = new FileInputStream(altPrivKeyFile);
		byte[] bufferForAltPrivKey = new byte[(int) altPrivKeyFile.length()];
		fileInputStream.read(bufferForAltPrivKey);
		sphincsCaPrivateKey = new SPHINCSPrivateKeyParameters(bufferForAltPrivKey);
		fileInputStream.close();
	}
	
	private void readCaRsaKeyPair() throws IOException, ClassNotFoundException {
		FileInputStream fileInputStream = new FileInputStream(new File("rsaCaPublicKey"));
		ObjectInputStream objectInputStream = new ObjectInputStream(fileInputStream);
		rsaCaPublicKey = (PublicKey) objectInputStream.readObject();
		fileInputStream = new FileInputStream(new File("rsaCaPrivateKey"));
		objectInputStream = new ObjectInputStream(fileInputStream);
		rsaCaPrivateKey = (PrivateKey) objectInputStream.readObject();
		objectInputStream.close();
		fileInputStream.close();
	}
	
	public X509CertificateGenerator() throws NoSuchAlgorithmException, IOException, ClassNotFoundException {
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		readCaRsaKeyPair();
		readSphincsKeys();
	}
	
	public void generateX509Certificate(String countryName,String organizationName,String orgnaizationalUnitName,String issuerCommonName,
			String subjectCommonName, String subjectAlternativeName,String caIssuersUrl, String oscpURL
			) throws NoSuchAlgorithmException, IOException, NoSuchProviderException, InvalidKeyException, SignatureException {
		
		//Version  ::=  INTEGER  {  v1(0), v2(1), v3(2)  }
		DERTaggedObject version = new DERTaggedObject(true, 0, new ASN1Integer(2));
		
		//CertificateSerialNumber  ::=  INTEGER
		ASN1Integer certificateSerialNumber = new ASN1Integer(BigInteger.valueOf(Math.abs(new Random().nextInt())));
		
		/*AlgorithmIdentifier  ::=  SEQUENCE  {
        algorithm OBJECT IDENTIFIER,
        parameters ANY DEFINED BY algorithm OPTIONAL  }*/
 
		ASN1EncodableVector signatureAlgorithmIdentifier = new ASN1EncodableVector();
		signatureAlgorithmIdentifier.add(new ASN1ObjectIdentifier(SIGNATURE_ALGORITHM_IDENTIFIER_OID));
		signatureAlgorithmIdentifier.add(DERNull.INSTANCE);
		DLSequence signatureAlgorithm = new DLSequence(signatureAlgorithmIdentifier);
		

		/*Name ::= CHOICE { rdnSequence  RDNSequence }
		RDNSequence ::= SEQUENCE OF RelativeDistinguishedName
		RelativeDistinguishedName ::=
		     SET SIZE (1..MAX) OF AttributeTypeAndValue*/
		 
		/*AttributeTypeAndValue ::= SEQUENCE {
		    type     AttributeType,
		    value    AttributeValue }*/
		 
		ASN1EncodableVector countryNameAsn1 = new ASN1EncodableVector();
		countryNameAsn1.add(new ASN1ObjectIdentifier(COUNTRY_NAME_OID));
		countryNameAsn1.add(new DERPrintableString(countryName));
		DLSequence countryNameAtv = new DLSequence(countryNameAsn1);
		 
		ASN1EncodableVector organizationNameAsn1 = new ASN1EncodableVector();
		organizationNameAsn1.add(new ASN1ObjectIdentifier(ORGANIZATION_NAME_OID));
		organizationNameAsn1.add(new DERPrintableString(organizationName));
		DLSequence organizationNameAtv = new DLSequence(organizationNameAsn1);
		 
		ASN1EncodableVector organizationalUnitNameAsn1 = new ASN1EncodableVector();
		organizationalUnitNameAsn1.add(new ASN1ObjectIdentifier(ORGANIZATIONAL_UNIT_NAME_OID));
		organizationalUnitNameAsn1.add(new DERPrintableString(orgnaizationalUnitName));
		DLSequence organizationalUnitNameAtv = new DLSequence(organizationalUnitNameAsn1);
		 
		ASN1EncodableVector issuerCommonNameAsn1 = new ASN1EncodableVector();
		issuerCommonNameAsn1.add(new ASN1ObjectIdentifier(ISSUER_COMMON_NAME));
		issuerCommonNameAsn1.add(new DERPrintableString(issuerCommonName));
		DLSequence issuerCommonNameAtv = new DLSequence(issuerCommonNameAsn1);
		 
		//RelativeDistinguishedName ::= SET SIZE (1..MAX) OF AttributeTypeAndValue
		DERSet countryNameSet = new DERSet(countryNameAtv);
		DERSet organizationNameSet = new DERSet(organizationNameAtv);
		DERSet organizationalUnitNameSet = new DERSet(organizationalUnitNameAtv);
		DERSet issuerCommonNameSet = new DERSet(issuerCommonNameAtv);
		 
		ASN1EncodableVector issuerRelativeDistinguishedName = new ASN1EncodableVector();
		issuerRelativeDistinguishedName.add(countryNameSet);
		issuerRelativeDistinguishedName.add(organizationNameSet);
		issuerRelativeDistinguishedName.add(organizationalUnitNameSet);
		issuerRelativeDistinguishedName.add(issuerCommonNameSet);
		 
		//RDNSequence ::= SEQUENCE OF RelativeDistinguishedName
		DLSequence issuerName = new DLSequence(issuerRelativeDistinguishedName);
		
		//Time ::= CHOICE { utcTime UTCTime, generalTime GeneralizedTime }
		DERUTCTime notBefore = new DERUTCTime(new Date(System.currentTimeMillis()));
		DERUTCTime notAfter = new DERUTCTime(new Date(System.currentTimeMillis() + (((1000L*60*60*24*30))*12)*3));
		ASN1EncodableVector Time = new ASN1EncodableVector();
		Time.add(notBefore);
		Time.add(notAfter);
		 
		/*Validity ::= SEQUENCE {
		     notBefore      Time,
		     notAfter       Time } */
		 
		DLSequence validity = new DLSequence(Time);
		
		//SubjectName - only need to change the common name
		ASN1EncodableVector subjCommonNameAsn1 = new ASN1EncodableVector();
		subjCommonNameAsn1.add(new ASN1ObjectIdentifier(SUBJECT_COMMON_NAME));
		subjCommonNameAsn1.add(new DERPrintableString(subjectAlternativeName));
		DLSequence subjectCommonNameATV = new DLSequence(subjCommonNameAsn1);
		 
		//RelativeDistinguishedName ::= SET SIZE (1..MAX) OF AttributeTypeAndValue
		DERSet subjectCommonNameSet = new DERSet(subjectCommonNameATV);
		ASN1EncodableVector subjectRelativeDistinguishedName = new ASN1EncodableVector();
		subjectRelativeDistinguishedName.add(countryNameSet);
		subjectRelativeDistinguishedName.add(organizationNameSet);
		subjectRelativeDistinguishedName.add(organizationalUnitNameSet);
		subjectRelativeDistinguishedName.add(subjectCommonNameSet);
		 
		//RDNSequence ::= SEQUENCE OF RelativeDistinguishedName
		DLSequence subjectName = new DLSequence(subjectRelativeDistinguishedName);
		
		/*SubjectPublicKeyInfo  ::=  SEQUENCE  {
	    algorithm            AlgorithmIdentifier,
	    subjectPublicKey     BIT STRING  }*/
	 
		///Generate the 2048-bit RSA Public Key  - PublicKey returns SubjectPublicKeyInfo by default (X.509 format)
		
		 
		//Convert public key bytes (in SubjectPublicKeyInfo format) to ASN1Sequence
		byte[] RSAPubKeyBytes = rsaCaPublicKey.getEncoded();
		ASN1Sequence subjectPublicKeyInfo = ASN1Sequence.getInstance(RSAPubKeyBytes);
		//Get the subjectPublicKey from SubjectPublicKeyInfo to calculate the keyIdentifier
		DERBitString subjectPublicKey = (DERBitString)subjectPublicKeyInfo.getObjectAt(1).toASN1Primitive();
		 
		//Calculate the keyIdentifier Rsa
		byte[] pubKeyBitStringBytes = subjectPublicKey.getBytes();
		Digest sha2 = new SHA256Digest();
		byte[] pubKeydigestBytes = new byte[sha2.getDigestSize()];
		sha2.update(pubKeyBitStringBytes,0,pubKeyBitStringBytes.length);
		sha2.doFinal(pubKeydigestBytes,0);
		DEROctetString keyIdentifier = new DEROctetString(pubKeydigestBytes);
		 
		//Subject Key Identifier
		ASN1EncodableVector subjectKeyIdentifierAsn1 = new ASN1EncodableVector();
		subjectKeyIdentifierAsn1.add(new ASN1ObjectIdentifier(SUBJECT_KEY_IDENTIFIER));
		subjectKeyIdentifierAsn1.add(new DEROctetString(keyIdentifier));
		DLSequence subjectKeyIdentifier = new DLSequence(subjectKeyIdentifierAsn1);
		 
		//Authority Key Identifier
		DERTaggedObject aki = new DERTaggedObject(false,0,keyIdentifier);
		ASN1EncodableVector akiVec = new ASN1EncodableVector();
		akiVec.add(aki);
		DLSequence akiSeq = new DLSequence(akiVec);
		ASN1EncodableVector authorityKeyIdentifierAsn1 = new ASN1EncodableVector();
		authorityKeyIdentifierAsn1.add(new ASN1ObjectIdentifier(AUTHORITY_KEY_IDENTIFIER));
		authorityKeyIdentifierAsn1.add(new DEROctetString(akiSeq));
		DLSequence authorityKeyIdentifier = new DLSequence(authorityKeyIdentifierAsn1);
		
		//Basic Constraints
		ASN1Boolean isCa = ASN1Boolean.getInstance(ASN1Boolean.TRUE);
		ASN1Integer pathLenConstraint = new ASN1Integer(0);
		ASN1EncodableVector basicConstraintStructure_ASN = new ASN1EncodableVector();
		basicConstraintStructure_ASN.add(isCa);
		basicConstraintStructure_ASN.add(pathLenConstraint);
		DLSequence basicConstraintSeq = new DLSequence(basicConstraintStructure_ASN);
		 
		ASN1EncodableVector basicConstraintExtension = new ASN1EncodableVector();
		basicConstraintExtension.add(new ASN1ObjectIdentifier(BASIC_CONSTRAINTS_OID));
		basicConstraintExtension.add(ASN1Boolean.TRUE); //Mark critical
		basicConstraintExtension.add(new DEROctetString(basicConstraintSeq));
		DLSequence basicConstraints = new DLSequence(basicConstraintExtension);
		
		//Subject Alternative Name
		DERTaggedObject rfc822Name = new DERTaggedObject(false, 1, new DERIA5String(subjectAlternativeName));
		DERTaggedObject directoryName = new DERTaggedObject(true, 4, subjectName); //directoryName explicitly tagged
		ASN1EncodableVector generalNamesVec = new ASN1EncodableVector();
		generalNamesVec.add(rfc822Name);
		generalNamesVec.add(directoryName);
		DLSequence generalNamesSeq = new DLSequence(generalNamesVec);
		 
		ASN1EncodableVector subjectAltname_ASN = new ASN1EncodableVector();
		subjectAltname_ASN.add(new ASN1ObjectIdentifier(SUBJECT_ALTERNATIVE_NAME_OID));
		subjectAltname_ASN.add(new DEROctetString(generalNamesSeq));
		DLSequence subjectAlternativeNameSeq = new DLSequence(subjectAltname_ASN);
	
		//Authority Information Access
		DERTaggedObject caIssuers = new DERTaggedObject(false, 6, new DERIA5String(caIssuersUrl));
		DERTaggedObject ocspUrlObject = new DERTaggedObject(false, 6, new DERIA5String(oscpURL));
		ASN1EncodableVector caIssuersAsn1 = new ASN1EncodableVector();
		caIssuersAsn1.add(new ASN1ObjectIdentifier(CA_ISSUERS_OID));
		caIssuersAsn1.add(caIssuers);
		DLSequence caIssuersSeq = new DLSequence(caIssuersAsn1);
		ASN1EncodableVector ocspAsn1 = new ASN1EncodableVector();
		ocspAsn1.add(new ASN1ObjectIdentifier(OSCP_OID));
		ocspAsn1.add(ocspUrlObject);
		DLSequence ocspSeq = new DLSequence(ocspAsn1);
		 
		ASN1EncodableVector accessSynAsn1= new ASN1EncodableVector();
		accessSynAsn1.add(caIssuersSeq);
		accessSynAsn1.add(ocspSeq);
		DLSequence authorityInformationAccessSyntaxSeq = new DLSequence(accessSynAsn1);
		 
		ASN1EncodableVector authorityInformationAccessAsn1 = new ASN1EncodableVector();
		authorityInformationAccessAsn1.add(new ASN1ObjectIdentifier(AUTHORITY_ACCESS_INFORMATION_OID));
		authorityInformationAccessAsn1.add(new DEROctetString(authorityInformationAccessSyntaxSeq));
		DLSequence authorityInformationAccess = new DLSequence(authorityInformationAccessAsn1);
		
		
		//Alternative signature Extension
		ASN1EncodableVector altSignatureAlgorithmIdentifierAsn1 = new ASN1EncodableVector();
		altSignatureAlgorithmIdentifierAsn1.add(new ASN1ObjectIdentifier(ALTERNATIVE_ALGORITHM_IDENTIFIER_OID));
		altSignatureAlgorithmIdentifierAsn1.add(DERNull.INSTANCE);
		DLSequence altSignatureAlgorithmIdenifierSeq = new DLSequence(altSignatureAlgorithmIdentifierAsn1); 
		ASN1EncodableVector altSignatureAlgorithmIdenifierExtension = new ASN1EncodableVector();
		altSignatureAlgorithmIdenifierExtension.add(new ASN1ObjectIdentifier(ALTERNATIVE_ALGORITHM_IDENTIFIER_EXTENSION_OID));
		altSignatureAlgorithmIdenifierExtension.add(ASN1Boolean.FALSE); //Mark non-critical
		altSignatureAlgorithmIdenifierExtension.add(new DEROctetString(altSignatureAlgorithmIdenifierSeq));
		DLSequence altSignatureAlgorithmIdentifier = new DLSequence(altSignatureAlgorithmIdenifierExtension);
		

		
	    
	  
	   
	  	//Calculate the alternative keyIdentifier
	  	Digest altSha2 = new SHA256Digest();
	  	byte[] altPubKeydigestBytes = new byte[altSha2.getDigestSize()];
	  	sha2.update(altPubKeydigestBytes,0,altPubKeydigestBytes.length);
	  	sha2.doFinal(altPubKeydigestBytes,0);
	  	DEROctetString altKeyIdentifier = new DEROctetString(altPubKeydigestBytes);
	  		 
	  	//altSubject Key Identifier
	  	ASN1EncodableVector altSubjectKeyIdentifier_ASN = new ASN1EncodableVector();
	  	altSubjectKeyIdentifier_ASN.add(new ASN1ObjectIdentifier(ALTERNTIVE_SUBJECT_KEY_INFO));
	  	altSubjectKeyIdentifier_ASN.add(ASN1Boolean.FALSE); //Mark non-critical
	  	altSubjectKeyIdentifier_ASN.add(new DEROctetString(altKeyIdentifier));
	  	DLSequence altSubjectKeyIdentifierExtension = new DLSequence(altSubjectKeyIdentifier_ASN);
	  	
	  	
	  	
	  	
		
		//Create Extensions
		ASN1EncodableVector extensionsAsn1 = new ASN1EncodableVector();
		extensionsAsn1.add(subjectKeyIdentifier);
		extensionsAsn1.add(authorityKeyIdentifier);
		extensionsAsn1.add(basicConstraints);
		extensionsAsn1.add(subjectAlternativeNameSeq);
		extensionsAsn1.add(authorityInformationAccess);
		extensionsAsn1.add(altSignatureAlgorithmIdentifier);
		extensionsAsn1.add(altSubjectKeyIdentifierExtension);

		DLSequence extensionsSeq = new DLSequence(extensionsAsn1);
		 
		DERTaggedObject extensions = new DERTaggedObject(true, 3, extensionsSeq);
		
		//PreTBSCertificate := SEQUENCE
		ASN1EncodableVector preTbsCertificateAsn1 = new ASN1EncodableVector();
		preTbsCertificateAsn1.add(version);
		preTbsCertificateAsn1.add(certificateSerialNumber);
		preTbsCertificateAsn1.add(issuerName);
		preTbsCertificateAsn1.add(validity);
		preTbsCertificateAsn1.add(subjectName);
		preTbsCertificateAsn1.add(subjectPublicKeyInfo);
		preTbsCertificateAsn1.add(extensions);
		DLSequence preTbsCertificate = new DLSequence(preTbsCertificateAsn1);
		
		//Create the signature value
		
		MessageSigner signer = new SPHINCS256Signer(new SHA512tDigest(256), new SHA512Digest());
		signer.init(true, sphincsCaPrivateKey);
		byte[] sig = signer.generateSignature(preTbsCertificate.getEncoded());
		DERBitString altSignatureValue = new DERBitString(sig);
		
		
		
		//Alternative signature Value
	  	ASN1EncodableVector altSignatureValueAsn1 = new ASN1EncodableVector();
	  	altSignatureValueAsn1.add(new ASN1ObjectIdentifier(ALTERNATIVE_SIGNATURE_VALUE_OID));
	  	altSignatureValueAsn1.add(ASN1Boolean.FALSE); //Mark non-critical
	  	altSignatureValueAsn1.add(new DEROctetString(altSignatureValue));
	  	DLSequence altSignatureValueExtension = new DLSequence(altSignatureValueAsn1);
	  	extensionsAsn1.add(altSignatureValueExtension);
	  	extensionsSeq = new DLSequence(extensionsAsn1);
	  	extensions = new DERTaggedObject(true, 3, extensionsSeq);
	  	
		
		//TBSCertificate := SEQUENCE
		ASN1EncodableVector tbsCertificateAsn1 = new ASN1EncodableVector();
		tbsCertificateAsn1.add(version);
		tbsCertificateAsn1.add(certificateSerialNumber);
		tbsCertificateAsn1.add(signatureAlgorithm);
		tbsCertificateAsn1.add(issuerName);
		tbsCertificateAsn1.add(validity);
		tbsCertificateAsn1.add(subjectName);
		tbsCertificateAsn1.add(subjectPublicKeyInfo);
		tbsCertificateAsn1.add(extensions);
	
		DLSequence tbsCertificate = new DLSequence(tbsCertificateAsn1);
		
		
		//Create the signature value
		byte[] tbsCertificateBytes = tbsCertificate.getEncoded();
		Signature rsaSigner = Signature.getInstance("SHA256WithRSA","BC");
		rsaSigner.initSign(rsaCaPrivateKey);
		rsaSigner.update(tbsCertificateBytes);
		byte[] signature = rsaSigner.sign();
		DERBitString signatureValue = new DERBitString(signature);
		
		
		
		
		//Create the certificate structure
		ASN1EncodableVector cert_ASN = new ASN1EncodableVector();
		cert_ASN.add(tbsCertificate);
		cert_ASN.add(signatureAlgorithm);
		cert_ASN.add(signatureValue);
		
		DLSequence certificate = new DLSequence(cert_ASN);
		
		File file = new File("certificate.crt");
        byte[] buf = certificate.getEncoded();

       
        FileOutputStream os = new FileOutputStream(file);
        os.write(buf);
        os.close();
	}
   
	public static void verifyConventionalSignature(DLSequence certificateFromFilesystem,PublicKey pk) throws Exception {
		DLSequence TBSCertificate = (DLSequence) certificateFromFilesystem.getObjectAt(0);
		DERBitString signature = (DERBitString) certificateFromFilesystem.getObjectAt(2);
		Signature signAlg = Signature.getInstance("SHA256withRSA","BC");
		signAlg.initVerify(pk);
		signAlg.update(TBSCertificate.getEncoded());
		if(!signAlg.verify(signature.getBytes()))
			throw new Exception("Stop!");
		System.out.println("Verification of conventional signature is successful!");
	}
	
	public static void verifyAlternativeSignatureSPHINCS(DLSequence certificateFromFilesystem,SPHINCSPublicKeyParameters pk) throws Exception {
		DLSequence tbsCertificate = (DLSequence) certificateFromFilesystem.getObjectAt(0);
		DERTaggedObject extenstionsTaggedObject = (DERTaggedObject) tbsCertificate.getObjectAt(7);
		DERSequence parse =  (DERSequence) extenstionsTaggedObject.getObjectParser(3, true);
		Iterator iter = (Iterator) parse.iterator();
		DERSequence possibleAsn1Object = null;
		DEROctetString alternativeSignature = null;
		ASN1EncodableVector Extensions_ASN = new ASN1EncodableVector();
		while(iter.hasNext()) {
			possibleAsn1Object = (DERSequence) iter.next();
			if(!ALTERNATIVE_SIGNATURE_VALUE_OID.equals(possibleAsn1Object.getObjectAt(0).toString())) {
				Extensions_ASN.add(possibleAsn1Object);
			}	
			if(ALTERNATIVE_SIGNATURE_VALUE_OID.equals(possibleAsn1Object.getObjectAt(0).toString())) {
				alternativeSignature =  (DEROctetString) possibleAsn1Object.getObjectAt(2);
			}
		}
		DLSequence Extensions = new DLSequence(Extensions_ASN);
		DERTaggedObject extensions = new DERTaggedObject(true, 3, Extensions);
		
		Iterator tbsCertificateIterator =  (Iterator) tbsCertificate.iterator();
		ASN1EncodableVector preTBSCertificate_ASN = new ASN1EncodableVector();
		Object possibleObject = null;
		DERTaggedObject taggedObject = null;
		DLSequence sequence = null;
		while(tbsCertificateIterator.hasNext()) {
			possibleObject = tbsCertificateIterator.next();
			if(!(possibleObject instanceof DERTaggedObject)) {
				if(possibleObject instanceof DLSequence) {
					sequence = (DLSequence) possibleObject;
					if(sequence.getObjectAt(0).toString().equals(SIGNATURE_ALGORITHM_IDENTIFIER_OID))
						continue;
				}
					preTBSCertificate_ASN.add((ASN1Encodable) possibleObject);
				continue;
			}
			else
				taggedObject = (DERTaggedObject) possibleObject;			
			if(taggedObject!=null && taggedObject.getTagNo() < 3) {
				preTBSCertificate_ASN.add((ASN1Encodable) taggedObject);
				
			}
		}
		
		preTBSCertificate_ASN.add((ASN1Encodable) extensions);
		DLSequence preTBSCertificate = new DLSequence(preTBSCertificate_ASN);
        byte[] preTBSCertificateBytes = preTBSCertificate.getEncoded();
        
		MessageSigner sphincsSigner = new SPHINCS256Signer(new SHA512tDigest(256), new SHA512Digest());
		sphincsSigner.init(false, pk);
		if(!sphincsSigner.verifySignature(preTBSCertificateBytes, Arrays.copyOfRange(new DERBitString(alternativeSignature).getBytes(),9,new DERBitString(alternativeSignature).getBytes().length)))
			throw new Exception("Verification failed");
		System.out.println("Verification of alternative signature is sucessful!");
		 	
	}

	private static byte[] readFileToByteArray(File file){
        FileInputStream fis = null;
        byte[] bArray = new byte[(int) file.length()];
        try{
            fis = new FileInputStream(file);
            fis.read(bArray);
            fis.close();        
            
        }catch(IOException ioExp){
            ioExp.printStackTrace();
        }
        return bArray;
    }
	private static DLSequence readCertificateFromFilesystem() throws IOException {
		File certificateToValidate = new File("certificate.crt");
		byte[] certificateBytes =  X509CertificateGenerator.readFileToByteArray(certificateToValidate);
		DLSequence certificateFromFilesystem = new DLSequence();
		certificateFromFilesystem =	(DLSequence) certificateFromFilesystem.fromByteArray(certificateBytes).toASN1Primitive();
		return certificateFromFilesystem;
	}
	
	public static void testVerificationOfMultipleKeyCertificatesSPHINCS(int amountOfIterations) throws Exception {
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		DLSequence certificateFromFilesystem = readCertificateFromFilesystem();
		FileInputStream	fileInputStream = new FileInputStream(new File("rsaCaPublicKey"));
		ObjectInputStream objectInputStream = new ObjectInputStream(fileInputStream);
		File sphincsPublickey = new File("sphincsCaPublicKey");
		PublicKey pubKey = (PublicKey) objectInputStream.readObject();
		fileInputStream = new FileInputStream(new File("sphincsCaPublicKey"));
		byte[] bufferForAltPubKey = new byte[(int) sphincsPublickey.length()];
		fileInputStream.read(bufferForAltPubKey);	
		SPHINCSPublicKeyParameters caPublicKey = new SPHINCSPublicKeyParameters(bufferForAltPubKey);
		fileInputStream.close();
		objectInputStream.close();		
		verifyConventionalSignature(certificateFromFilesystem,pubKey);
		caPublicKey = new SPHINCSPublicKeyParameters(bufferForAltPubKey);
		verifyAlternativeSignatureSPHINCS(certificateFromFilesystem, caPublicKey);
	
	}
	
}
