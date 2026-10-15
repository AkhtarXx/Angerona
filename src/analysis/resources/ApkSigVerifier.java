import com.android.apksig.ApkVerifier;
import java.io.File;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;

/** Minimal stdout-compatible verifier backed by Google's apksig library. */
public final class ApkSigVerifier {
    private static String sha256(byte[] value) throws Exception {
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(value);
        StringBuilder out = new StringBuilder();
        for (byte b : digest) out.append(String.format("%02x", b));
        return out.toString();
    }

    public static void main(String[] args) throws Exception {
        if (args.length != 1) {
            System.err.println("usage: ApkSigVerifier APK");
            System.exit(2);
        }
        ApkVerifier.Result result = new ApkVerifier.Builder(new File(args[0])).build().verify();
        System.out.println("Verified: " + result.isVerified());
        System.out.println("Verified using v1 scheme: " + result.isVerifiedUsingV1Scheme());
        System.out.println("Verified using v2 scheme: " + result.isVerifiedUsingV2Scheme());
        System.out.println("Verified using v3 scheme: "
                + (result.isVerifiedUsingV3Scheme() || result.isVerifiedUsingV31Scheme()));
        System.out.println("Verified using v4 scheme: " + result.isVerifiedUsingV4Scheme());
        int index = 1;
        for (X509Certificate certificate : result.getSignerCertificates()) {
            System.out.println("Signer #" + index + " certificate SHA-256 digest: "
                    + sha256(certificate.getEncoded()));
            index++;
        }
        if (!result.isVerified()) {
            for (ApkVerifier.IssueWithParams issue : result.getAllErrors()) {
                System.err.println(issue.toString());
            }
            System.exit(1);
        }
    }
}
