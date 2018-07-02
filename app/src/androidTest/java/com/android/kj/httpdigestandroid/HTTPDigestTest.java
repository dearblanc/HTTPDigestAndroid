package com.android.kj.httpdigestandroid;

import org.junit.Test;

import static com.android.kj.httpdigestandroid.DigestConstants.HTTP_GET;
import static org.junit.Assert.assertEquals;

public class HTTPDigestTest {

    @Test
    public void getAuthHeader() {
        /*  HTTP Digest Access Authentication
         *  Example with SHA-256 and MD5
         *  https://tools.ietf.org/html/rfc7616#page-17
         */
        WWWAuthenticate trial =
                WWWAuthenticate.parseHeader(
                        "Digest "
                                + "realm=\"http-auth@example.org\","
                                + "qop=\"auth, auth-int\","
                                + "algorithm=SHA-256,"
                                + "nonce=\"7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v\","
                                + "opaque=\"FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS\"");
        HTTPDigest digest =
                new HTTPDigest(
                        new Client(
                                "Mufasa",
                                "Circle of Life",
                                "http://www.example.org/dir/index.html",
                                HTTP_GET),
                        trial);
        digest.forceCnonceForTest("f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ\"");
        String auth = digest.getAuthHeader();
        assertEquals(
                "Digest username=\"Mufasa\","
                        + "realm=\"http-auth@example.org\","
                        + "uri=\"/dir/index.html\","
                        + "algorithm=SHA-256,"
                        + "nonce=\"7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v\","
                        + "nc=00000001,"
                        + "cnonce=\"f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ\","
                        + "qop=auth,"
                        + "response=\"753927fa0e85d155564e2e272a28d1802ca10daf449"
                        + "6794697cf8db5856cb6c1\","
                        + "opaque=\"FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS\"",
                auth);

        WWWAuthenticate trial2 =
                WWWAuthenticate.parseHeader(
                        "Digest "
                                + "realm=\"http-auth@example.org\","
                                + "qop=\"auth, auth-int\","
                                + "algorithm=MD5,"
                                + "nonce=\"7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v\","
                                + "opaque=\"FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS\"");
        HTTPDigest digest2 =
                new HTTPDigest(
                        new Client(
                                "Mufasa",
                                "Circle of Life",
                                "http://www.example.org/dir/index.html",
                                HTTP_GET),
                        trial2);
        digest2.forceCnonceForTest("f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ\"");
        String auth2 = digest2.getAuthHeader();

        assertEquals(
                "Digest username=\"Mufasa\","
                        + "realm=\"http-auth@example.org\","
                        + "uri=\"/dir/index.html\","
                        + "algorithm=MD5,"
                        + "nonce=\"7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v\","
                        + "nc=00000001,"
                        + "cnonce=\"f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ\","
                        + "qop=auth,"
                        + "response=\"8ca523f5e9506fed4657c9700eebdbec\","
                        + "opaque=\"FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS\"",
                auth2);
    }
}
