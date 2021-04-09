/**
 * 
 */
package com.pspl.www.crypto;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.List;

/**
 * @author C1267
 *
 */
public class VerifyMessage {

	/**
	 * @param args
	 */
	private List<byte[]> list;

	static String strEncSourceFile = "TAXiON_ENC_SampleFile\\RES_TAX_DET_CONS_GSTR1_082018_SAP_NORMAL_SBI_test1231199.csv";
	static String strDecSourceFile = "TAXiON_DEC_SampleFile\\RES_TAX_DET_CONS_GSTR1_082018_SAP_NORMAL_SBI_test1231199.csv";

	static String strENCSourceFile_HASHSign = "TAXiON_ENC_SampleFile\\RES_TAX_DET_CONS_GSTR1_082018_SAP_NORMAL_SBI_test1231199.csv_973c71eba2f6a888fb1b3302b8c2f53d43a1fe55fda340967d138d71b44d6074";
	static String strPubKeyPath_TAXiON = "TaxEngineKey\\TAXiONKey\\TCS_20210127_20210127_PUB.key";

	public static byte[] getFileInBytes(File f) throws IOException {

		FileInputStream fis = new FileInputStream(f);
		byte[] fbytes = new byte[(int) f.length()];
		fis.read(fbytes);
		fis.close();
		return fbytes;

	}

	// Method for signature verification that initializes with the Public Key,
	// updates the data to be verified and then verifies them using the signature
	public boolean verifySignature(byte[] data, byte[] signature, String keyFile) throws Exception {
		Signature sig = Signature.getInstance("SHA1withRSA");
		sig.initVerify(getPublic(keyFile));
		sig.update(data);

		return sig.verify(signature);
	}

	// Method to retrieve the Public Key from a file
	public static PublicKey getPublic(String filename) throws Exception {
		byte[] keyBytes = Files.readAllBytes(new File(filename).toPath());
		X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
		KeyFactory kf = KeyFactory.getInstance("RSA");
		return kf.generatePublic(spec);
	}

//	private static String bytesToHex(byte[] hash) {
//	    StringBuilder hexString = new StringBuilder(2 * hash.length);
//	    for (int i = 0; i < hash.length; i++) {
//	        String hex = Integer.toHexString(0xff & hash[i]);
//	        if(hex.length() == 1) {
//	            hexString.append('0');
//	        }
//	        hexString.append(hex);
//	    }
//	    return hexString.toString();
//	}
	
//	private static void VerifySignature()
//	{
//		try {
//			Signature sig = Signature.getInstance("SHA1withRSA");
//			sig.initVerify(getPublic(strPubKeyPath_TAXiON));
//			sig.update(getFileInBytes(new File(strEncSourceFile)));
//
//			System.out.print("Signature Matching Status -" + sig.verify(getFileInBytes(new File(strENCSourceFile_HASHSign))));
//
//			// MessageDigest digest = MessageDigest.getInstance("SHA-256");
////			byte[] encodedhash = digest.digest(getFileInBytes(new File(strSourceFile)));
////			    System.out.println(bytesToHex(encodedhash));
//		} catch (Exception e) {
//			System.out.print("Exception - " + e.getMessage().toString());
//			// TODO: handle exception
//		}
//
//	}
	
	public static void main(String[] args) throws Exception {

		try {
			Signature sig = Signature.getInstance("SHA1withRSA");
			sig.initVerify(getPublic(strPubKeyPath_TAXiON));
			sig.update(getFileInBytes(new File(strEncSourceFile)));

			System.out.print("Signature Matching Status -" + sig.verify(getFileInBytes(new File(strENCSourceFile_HASHSign))));

			// MessageDigest digest = MessageDigest.getInstance("SHA-256");
//			byte[] encodedhash = digest.digest(getFileInBytes(new File(strSourceFile)));
//			    System.out.println(bytesToHex(encodedhash));
		} catch (Exception e) {
			System.out.print("Exception - " + e.getMessage().toString());
			// TODO: handle exception
		}
	}
}