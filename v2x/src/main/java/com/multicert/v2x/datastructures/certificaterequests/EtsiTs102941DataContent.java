package com.multicert.v2x.datastructures.certificaterequests;

import com.multicert.v2x.asn1.coer.COERChoice;
import com.multicert.v2x.asn1.coer.COERChoiceEnumeration;
import com.multicert.v2x.asn1.coer.COEREncodable;
import com.multicert.v2x.datastructures.certificaterequests.Enrollment.InnerEcResponse;
import com.multicert.v2x.datastructures.message.secureddata.EtsiTs103097Data;

import java.io.IOException;

import static com.multicert.v2x.datastructures.certificaterequests.EtsiTs102941DataContent.EtsiTs102941DataContentTypes.ENROLLMENT_RESPONSE;


public class EtsiTs102941DataContent extends COERChoice
{
    public enum EtsiTs102941DataContentTypes implements COERChoiceEnumeration
    {
        ENROLLMENT_REQUEST, //TODO EXTEND OTHER TYPES HERE
        ENROLLMENT_RESPONSE;

        public int myOrdinal()
        {
            return this.ordinal();
        }

        @Override
        public COEREncodable getEncodableType() throws IOException
        {

            switch(this)
            {
                case ENROLLMENT_REQUEST:
                    return new EtsiTs103097Data(); //corresponds to the InnerEcRequestSignedForPOP
                default:
                    return new InnerEcResponse();
            }
        }
    }

    /**
     * Constructor used when encoding the type ENROLLMENT_REQUEST
     */
    public EtsiTs102941DataContent(EtsiTs102941DataContentTypes type, EtsiTs103097Data InnerECRequestSignedForPOP)
    {
        super(type, InnerECRequestSignedForPOP);
    }

    /**
     * Constructor used when encoding the type ENROLLMENT_RESPONSE
     */
    public EtsiTs102941DataContent(InnerEcResponse innerEcResponse)
    {
        super(ENROLLMENT_RESPONSE, innerEcResponse);
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
    public EtsiTs102941DataContentTypes getType()
    {
        return (EtsiTs102941DataContentTypes) choice;
    }
}
