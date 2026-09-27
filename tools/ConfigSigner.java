// Signs the remote config so the app only accepts configs made by you.
//
//   java tools\ConfigSigner.java genkey <keysDir>            creates private.pk8 + public.txt (once)
//   java tools\ConfigSigner.java sign <keysDir> <config.json> writes <config.json>.sig
//
// ECDSA P-256 / SHA-256 (verifiable on every Android version). Keep private.pk8 secret
// and out of git; public.txt goes into the app (RemoteConfigKey.kt).
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

public class ConfigSigner {
    public static void main(String[] args) throws Exception {
        Path keys = Path.of(args[1]);
        switch (args[0]) {
            case "genkey" -> {
                Files.createDirectories(keys);
                if (Files.exists(keys.resolve("private.pk8"))) throw new IllegalStateException("key already exists");
                var gen = KeyPairGenerator.getInstance("EC");
                gen.initialize(new ECGenParameterSpec("secp256r1"));
                var pair = gen.generateKeyPair();
                Files.write(keys.resolve("private.pk8"), pair.getPrivate().getEncoded());
                String pub = Base64.getEncoder().encodeToString(pair.getPublic().getEncoded());
                Files.writeString(keys.resolve("public.txt"), pub);
                System.out.println(pub);
            }
            case "sign" -> {
                var key = KeyFactory.getInstance("EC").generatePrivate(
                    new PKCS8EncodedKeySpec(Files.readAllBytes(keys.resolve("private.pk8"))));
                Path config = Path.of(args[2]);
                var sig = Signature.getInstance("SHA256withECDSA");
                sig.initSign(key);
                sig.update(Files.readAllBytes(config));
                Files.writeString(Path.of(config + ".sig"), Base64.getEncoder().encodeToString(sig.sign()));
                System.out.println("signed " + config);
            }
            default -> throw new IllegalArgumentException("genkey | sign");
        }
    }
}
