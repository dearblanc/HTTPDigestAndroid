package com.android.kj.httpdigestandroid;

import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class WWWAuthenticateTest {
    private WWWAuthenticate mWWWAuthenticate;

    @Test
    public void parseHeader() {
        mWWWAuthenticate =
                WWWAuthenticate.parseHeader(
                        "Digest "
                                + "realm=\"http-auth@example.org\","
                                + "qop=\"auth, auth-int\","
                                + "algorithm=SHA-256,"
                                + "nonce=\"7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v\","
                                + "opaque=\"FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS\"");
    }

    @Test
    public void getRealm() {
        parseHeader();
        assertEquals("http-auth@example.org", mWWWAuthenticate.getRealm());
    }

    @Test
    public void getDomains() {
        parseHeader();
        assertEquals(null, mWWWAuthenticate.getDomains());
    }

    @Test
    public void getNonce() {
        parseHeader();
        assertEquals("7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v", mWWWAuthenticate.getNonce());
    }

    @Test
    public void getOpaque() {
        parseHeader();
        assertEquals("FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS", mWWWAuthenticate.getOpaque());
    }

    @Test
    public void getStale() {
        parseHeader();
        assertEquals(null, mWWWAuthenticate.getStale());
    }

    @Test
    public void getAlgorithm() {
        parseHeader();
        assertEquals("SHA-256", mWWWAuthenticate.getAlgorithm());
    }

    @Test
    public void getQop() {
        parseHeader();
        assertEquals("auth, auth-int", mWWWAuthenticate.getQop());
    }

    @Test
    public void getCharSet() {
        parseHeader();
        assertEquals(null, mWWWAuthenticate.getCharSet());
    }

    @Test
    public void getUserHash() {
        parseHeader();
        assertEquals(null, mWWWAuthenticate.getUserHash());
    }

    @Test
    public void validAlgorithm() {
        parseHeader();
        assertEquals(true, mWWWAuthenticate.validAlgorithm(mWWWAuthenticate.getAlgorithm()));
    }
}
