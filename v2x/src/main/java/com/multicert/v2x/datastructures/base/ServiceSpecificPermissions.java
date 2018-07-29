package com.multicert.v2x.datastructures.base;

import com.multicert.v2x.asn1.coer.COERChoice;
import com.multicert.v2x.asn1.coer.COERChoiceEnumeration;
import com.multicert.v2x.asn1.coer.COEREncodable;
import com.multicert.v2x.asn1.coer.COEROctetString;

/**
 * This class represents the Service Specific Permissions (SSP) relevant to a given entry in a PsidSsp.
 * The meaning of the SSP is permissions within a specific application (indicated by psid)
 *
 * @author Leonardo Gonçalves, leonardo.goncalves@multicert.com
 *
 * */
public class ServiceSpecificPermissions extends COERChoice
{
    public enum ServiceSpecificPermissionsTypes implements COERChoiceEnumeration
    {
        OPAQUE();

        @Override
        public int myOrdinal()
        {
            return this.ordinal();
        }

        @Override
        public COEREncodable getEncodableType()
        {
            return new COEROctetString();
        }
    }

    /**
     * Constructor used when encoding.
     */
    public ServiceSpecificPermissions(ServiceSpecificPermissionsTypes choice, byte[] value)
    {
        super(choice, new COEROctetString(value,0, null) );
    }

    /**
     * Constructor used when decoding.
     */
    public ServiceSpecificPermissions()
    {
        super(ServiceSpecificPermissionsTypes.class);
    }

}
