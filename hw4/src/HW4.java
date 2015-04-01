import java.io.FileInputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

import javax.crypto.Cipher;

public class HW4 {

	/**
	 * @param args
	 */
	public static void main(String[] args) {
		CertificateFactory cf = null;

		FileInputStream fisRaghuPub = null;
		FileInputStream fisRaghuPri = null;
		FileInputStream fisCAPub = null;

		X509Certificate certRaghu = null;
		X509Certificate certCA = null;

		try {
			cf = CertificateFactory.getInstance("X.509");

			fisRaghuPub = new FileInputStream("certificate/Raghupub.cer");
			fisRaghuPri = new FileInputStream("certificate/Raghupri.pfx");
			fisCAPub = new FileInputStream("certificate/Trustcenter.cer");

			certRaghu = (X509Certificate) cf.generateCertificate(fisRaghuPub);

			// Verify Raghu’s certificate.
			// 1. Print the certificate.
			System.out.println("==============================================================");
			System.out.println("================  1. print the certificate  ==================");
			System.out.println("==============================================================");
			System.out.println(certRaghu.toString());
			System.out.println();

			// 2. Print Raghu’s public and private key
			System.out.println("==============================================================");
			System.out.println("=========  2. print Raghu's public and private key  ==========");
			System.out.println("==============================================================");

			// public key
			System.out.println("Public key:");
			System.out.println(certRaghu.getPublicKey().toString());
			System.out.println();

			// private key
			System.out.println("Private key:");
			// get user password and file input stream
			KeyStore store = KeyStore.getInstance("pkcs12", "SunJSSE");
			char[] password = "raghu".toCharArray();
			store.load(fisRaghuPri, password);

			// get the first alias
			String alias = null;
			Enumeration<String> aliases = store.aliases();
			while (aliases.hasMoreElements()) {
				// System.out.println(aliases.nextElement());
				if (null == alias) {
					alias = aliases.nextElement();
					break;
				}
			}

			// use the alias to get the key
			Key key = store.getKey(alias, password);
			System.out.println(byteArrayToHex(key.getEncoded()));
			System.out.println();

			// 3. Print the public Key of Certification Authority.
			System.out.println("==============================================================");
			System.out.println("====  3. Print the public Key of Certification Authority  ====");
			System.out.println("==============================================================");
			certCA = (X509Certificate) cf.generateCertificate(fisCAPub);
			System.out.println("Public key:");
			System.out.println(certCA.getPublicKey().toString());
			System.out.println();

			// 4. Print the signature on TA’s certificate
			System.out.println("==============================================================");
			System.out.println("=======   4. Print the signature on TA’s certificate  ========");
			System.out.println("==============================================================");
			System.out.println(byteArrayToHex(certRaghu.getSignature()));
			System.out.println();

			// 5. Encrypt and Decrypt “Our names are << names>>. We are enrolled in CSE 539." using RSA
			String plainText = "Our names are Lei Chen & Bin Zhu. We are enrolled in CSE 539";
			System.out.println("==============================================================");
			System.out.println("=== 5. Encrypt and decrypt the following string using RSA  ===");
			System.out.println("==============================================================");
			System.out.println("Plain text:");
			System.out.println(plainText);
			System.out.println();

			System.out.println("Cipher text:");
			byte[] cipherText = encrypt(plainText, certRaghu.getPublicKey());
			System.out.println(byteArrayToHex(cipherText));
			System.out.println();

			System.out.println("Decrypted text:");
			System.out.println(decrypt(cipherText, key));
			System.out.println();

			System.out.println("==============================================================");
			System.out.println("=========== 6. Verify Raghu's certificate  ===================");
			System.out.println("==============================================================");
			try {
				certRaghu.checkValidity();
				System.out.println("Valid!");
			} catch (Exception e) {
				System.out.println("Invalid! (" + e.getMessage() + ")");
			}

		} catch (Exception e) {
			e.printStackTrace();
		} finally {
			try {
				if (null != fisRaghuPub)
					fisRaghuPub.close();
				if (null != fisRaghuPri)
					fisRaghuPri.close();
				if (null != fisCAPub)
					fisCAPub.close();
			} catch (Exception ex) {
				ex.printStackTrace();
			}
		}
	}

	public static String byteArrayToHex(byte[] a) {
		StringBuilder sb = new StringBuilder(a.length * 2);
		for (byte b : a)
			sb.append(String.format("%02x ", b & 0xff));
		return sb.toString();
	}

	public static byte[] encrypt(String text, Key key) throws Exception {
		byte[] cipherText = null;
		final Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.ENCRYPT_MODE, key);
		cipherText = cipher.doFinal(text.getBytes());
		return cipherText;
	}

	public static String decrypt(byte[] text, Key key) throws Exception {
		byte[] dectyptedText = null;
		final Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.DECRYPT_MODE, key);
		dectyptedText = cipher.doFinal(text);
		return new String(dectyptedText);
	}
}
