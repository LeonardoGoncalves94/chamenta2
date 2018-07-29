package com.multicert.v2x.datastructures.certificate;

import com.multicert.v2x.asn1.coer.COERChoice;
import com.multicert.v2x.asn1.coer.COERChoiceEnumeration;
import com.multicert.v2x.asn1.coer.COEREncodable;
import com.multicert.v2x.asn1.coer.COERNull;
import com.multicert.v2x.datastructures.base.Hostname;
import com.multicert.v2x.datastructures.base.IdentifiedRegion;

public class CertificateId extends COERChoice
{
    //TODO Missing the components linkageData and binaryId. ETSI certificates have those always ABSENT

    public enum CertificateIdTypes implements COERChoiceEnumeration
    {
        NAME,
        NONE,
        BINARY_ID, // not used by etsi ts 103 097
        LINKAGE_DATA; //notused by etsu ts 103 097

        public int myOrdinal() {
            return this.ordinal();
        }

        @Override
        public COEREncodable getEncodableType()
        {
            switch(this)
            {
                case NAME:
                    return new Hostname();
                default:
                    return new COERNull();

            }
        }
    }

    /**
     * Constructor used when encoding the type NAME
     */
    public CertificateId(Hostname name) throws IllegalArgumentException
    {
        super(CertificateIdTypes.NAME, name); //posso passar o int ordinal em vez do item da enum? super(CertificateIdChoices.NAME.myOrdinal(), name);
    }

    /**
     * Constructor used when encoding and decoding  the type NONE
     */
    public CertificateId() throws IllegalArgumentException
    {
        super(CertificateIdTypes.NONE, new COERNull());
        this.choiceEnum = CertificateIdTypes.class;
    }


    /**
     *
     * @return the choice of CertificateId, which is an item of CertificateIdChoices
     */
    public CertificateIdTypes getChoice()
    {
        return (CertificateIdTypes) choice;
    }
}
