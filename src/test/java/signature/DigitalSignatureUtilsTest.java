package signature;

import asymmetric.AsymmerticEncryptionUtil;
import org.junit.Test;

import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.util.Arrays;

import static org.junit.Assert.assertTrue;

public class DigitalSignatureUtilsTest {
    @Test
    public void digitalSignatureRoutine() throws Exception{
        //going to use the txt file in resources as example
        URL uri=this.getClass().getClassLoader().getResource("goals of encryption.txt");
        Path path= Paths.get(uri.toURI());
        byte[] input= Files.readAllBytes(path);

        KeyPair keyPair= AsymmerticEncryptionUtil.generateRSAKeyPair();
        byte[] signature=DigitalSignatureUtils.createDigitalSignature(input,keyPair.getPrivate());
        System.out.println(Arrays.toString(signature));

        assertTrue(DigitalSignatureUtils.verifyDigitalSignature(input, signature,keyPair.getPublic()));
    }

}