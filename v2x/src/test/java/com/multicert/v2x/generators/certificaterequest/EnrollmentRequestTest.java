package com.multicert.v2x.generators.certificaterequest;

import com.multicert.v2x.IdentifiedRegions.Countries;
import com.multicert.v2x.PkiGenerator;
import com.multicert.v2x.cryptography.CryptoHelper;
import com.multicert.v2x.datastructures.base.Duration;
import com.multicert.v2x.datastructures.base.GeographicRegion;
import com.multicert.v2x.datastructures.base.Signature;
import com.multicert.v2x.datastructures.base.ValidityPeriod;
import com.multicert.v2x.datastructures.certificate.EtsiTs103097Certificate;
import com.multicert.v2x.datastructures.message.secureddata.EtsiTs103097Data;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.security.KeyPair;
import java.util.Date;


public class EnrollmentRequestTest
{
    @Test
    public void testEncodeAndDecode() throws Exception
    {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(baos);

        CryptoHelper cryptoHelper = new CryptoHelper("BC");
        EnrollmentRequest requestGenerator = new EnrollmentRequest(cryptoHelper,false);
        PkiGenerator pki = new PkiGenerator(); //generate a simple pki

        KeyPair keyPair = cryptoHelper.genKeyPair(Signature.SignatureTypes.ECDSA_NIST_P256_SIGNATURE, "alias1"); //a keypair to be certified
        Signature.SignatureTypes keyPairAlgorithm = Signature.SignatureTypes.ECDSA_NIST_P256_SIGNATURE;

        ValidityPeriod validityPeriod = new ValidityPeriod(new Date(), Duration.DurationTypes.YEARS, 3);
        Countries.CountryTypes[] countries = {Countries.CountryTypes.SPAIN, Countries.CountryTypes.PORTUGAL};
        GeographicRegion region = Countries.getGeographicRegion(countries);
        EtsiTs103097Certificate enrollmentCACert = pki.getEnrollmentCA(); // the certificate of the target enrollment CA

        EtsiTs103097Data request = requestGenerator.generateEcRequest("123456789",keyPair,keyPairAlgorithm,"someHostname",validityPeriod,region,3,2,enrollmentCACert);
        request.encode(dos);
        System.out.println(request.toString());

        DataInputStream dis = new DataInputStream(new ByteArrayInputStream(baos.toByteArray()));
        EtsiTs103097Data decodedRequest = new EtsiTs103097Data();
        decodedRequest.decode(dis);
        System.out.println(decodedRequest.toString());

    }

}