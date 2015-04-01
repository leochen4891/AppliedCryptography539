import java.io.File;
import java.io.FileInputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public class HW4 {

	/**
	 * @param args
	 */
	public static void main(String[] args) {
		File file = new File("certificate/Raghupub.cer");
		FileInputStream fis = null;

		try {
			fis = new FileInputStream(file);

			CertificateFactory cf = CertificateFactory.getInstance("X.509");
			X509Certificate cert = (X509Certificate) cf.generateCertificate(fis);

			System.out.println(cert.toString());
			// int size = fis.available();
			// System.out.println("Total file size to read (in bytes) : " + size);
			//
			// int content;
			// for (int i = 0; i < size; i++) {
			// content = fis.read();
			// System.out.print(String.format("%x ", content));
			// }

		} catch (Exception e) {
			e.printStackTrace();
		} finally {
			try {
				if (fis != null)
					fis.close();
			} catch (Exception ex) {
				ex.printStackTrace();
			}
		}
	}
}
