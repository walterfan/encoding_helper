package com.github.walterfan.util;

import org.junit.Test;

import static org.junit.Assert.*;

public class EncodeUtilsTest {

    @Test
    public void testUrlEncode() {
        String originStr = "a=1&b=2&c=3+4&d=  @";
        String encodedStr = EncodeUtils.urlEncode(originStr);
        System.out.println(encodedStr);
        String decodedStr = EncodeUtils.urlDecode(encodedStr);
        assertEquals(decodedStr, originStr);
    }
}