//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.3.2 
// See <a href="https://javaee.github.io/jaxb-v2/">https://javaee.github.io/jaxb-v2/</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2023.05.02 at 09:31:12 AM CEST 
//


package de.init.seal_service.visual.profile;

import javax.xml.bind.annotation.XmlEnum;
import javax.xml.bind.annotation.XmlEnumValue;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for typeType.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * <p>
 * <pre>
 * &lt;simpleType name="typeType"&gt;
 *   &lt;restriction base="{http://www.w3.org/2001/XMLSchema}string"&gt;
 *     &lt;enumeration value="alphanum"/&gt;
 *     &lt;enumeration value="string"/&gt;
 *     &lt;enumeration value="multistring"/&gt;
 *     &lt;enumeration value="binary"/&gt;
 *     &lt;enumeration value="date"/&gt;
 *   &lt;/restriction&gt;
 * &lt;/simpleType&gt;
 * </pre>
 * 
 */
@XmlType(name = "typeType")
@XmlEnum
public enum TypeType {

    @XmlEnumValue("alphanum")
    ALPHANUM("alphanum"),
    @XmlEnumValue("string")
    STRING("string"),
    @XmlEnumValue("multistring")
    MULTISTRING("multistring"),
    @XmlEnumValue("binary")
    BINARY("binary"),
    @XmlEnumValue("date")
    DATE("date");
    private final String value;

    TypeType(String v) {
        value = v;
    }

    public String value() {
        return value;
    }

    public static TypeType fromValue(String v) {
        for (TypeType c: TypeType.values()) {
            if (c.value.equals(v)) {
                return c;
            }
        }
        throw new IllegalArgumentException(v);
    }

}
