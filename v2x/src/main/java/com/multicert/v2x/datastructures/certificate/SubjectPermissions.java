package com.multicert.v2x.datastructures.certificate;

import com.multicert.v2x.asn1.coer.COERChoice;
import com.multicert.v2x.asn1.coer.COERChoiceEnumeration;
import com.multicert.v2x.asn1.coer.COEREncodable;
import com.multicert.v2x.asn1.coer.COERNull;
import com.multicert.v2x.datastructures.base.SequenceOfPsidSspRange;
import com.multicert.v2x.datastructures.base.ServiceSpecificPermissions;

public class SubjectPermissions extends COERChoice
{
  public enum SubjectPermissionsTypes implements COERChoiceEnumeration
  {
      EXPLICIT,
      ALL;

      @Override
      public int myOrdinal()
      {
          return this.ordinal();
      }

      @Override
      public COEREncodable getEncodableType()
      {
          switch (this)
          {
              case EXPLICIT:
                  return new SequenceOfPsidSspRange();
                  default:
                      return new COERNull();
          }
      }
  }

    /**
     * Constructor used when encoding.
     *
     * @param type the type of SubjectPermissions
     * @param value set if type is explicit otherwise null.
     */
    public SubjectPermissions(SubjectPermissionsTypes type, SequenceOfPsidSspRange value) throws IllegalArgumentException
    {
        super(type, (type == SubjectPermissionsTypes.ALL ? new COERNull(): value));
    }

    /**
     * Constructor used when decoding.
     */
    public SubjectPermissions()
    {
        super(SubjectPermissionsTypes.class);
    }

}
