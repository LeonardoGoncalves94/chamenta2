package com.multicert.v2x.datastructures.certificaterequests;

import com.multicert.v2x.asn1.coer.COERChoice;
import com.multicert.v2x.asn1.coer.COERChoiceEnumeration;
import com.multicert.v2x.asn1.coer.COEREncodable;
import com.multicert.v2x.datastructures.message.secureddata.Ieee1609Dot2Data;


public class EtsiTs102941DataContent extends COERChoice
{
    public enum EtsiTs102941DataContentTypes implements COERChoiceEnumeration
    {
        ENROLLMENT_REQUEST; //TODO EXTEND OTHER TYPES HERE

        public int myOrdinal()
        {
            return this.ordinal();
        }

        @Override
        public COEREncodable getEncodableType()
        {
            return new Ieee1609Dot2Data();
        }
    }

    /**
     * Constructor used when encoding
     */
    public EtsiTs102941DataContent(EtsiTs102941DataContentTypes type, Ieee1609Dot2Data InnerECRequestSignedForPOP)
    {
        super(type, InnerECRequestSignedForPOP);
    }

    /**
     * Constructor used when decoding.
     */
    public EtsiTs102941DataContent()
    {
        super(EtsiTs102941DataContentTypes.class);
    }

    /**
     * Returns the unit of the Duration, which is an item of DurationChoices
     */
    public EtsiTs102941DataContentTypes getChoice()
    {
        return (EtsiTs102941DataContentTypes) choice;
    }
}
