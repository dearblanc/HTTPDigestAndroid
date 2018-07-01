package com.android.kj.httpdigestandroid;

import java.net.MalformedURLException;
import java.net.URL;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

import static com.android.kj.httpdigestandroid.DigestConstants.ALGORITHM;
import static com.android.kj.httpdigestandroid.DigestConstants.ALGORITHM_MD5;
import static com.android.kj.httpdigestandroid.DigestConstants.ALGORITHM_SESSION_VARIANT;
import static com.android.kj.httpdigestandroid.DigestConstants.CNONCE;
import static com.android.kj.httpdigestandroid.DigestConstants.COLON;
import static com.android.kj.httpdigestandroid.DigestConstants.COMMA;
import static com.android.kj.httpdigestandroid.DigestConstants.DOUBLE_QUOTATION;
import static com.android.kj.httpdigestandroid.DigestConstants.EQUALS;
import static com.android.kj.httpdigestandroid.DigestConstants.NC;
import static com.android.kj.httpdigestandroid.DigestConstants.NONCE;
import static com.android.kj.httpdigestandroid.DigestConstants.OPAQUE;
import static com.android.kj.httpdigestandroid.DigestConstants.QOP;
import static com.android.kj.httpdigestandroid.DigestConstants.QOP_AUTH_INTEGRATION;
import static com.android.kj.httpdigestandroid.DigestConstants.REALM;
import static com.android.kj.httpdigestandroid.DigestConstants.RESPONSE;
import static com.android.kj.httpdigestandroid.DigestConstants.TRUE;
import static com.android.kj.httpdigestandroid.DigestConstants.TYPICAL_DIGEST_TOKEN;
import static com.android.kj.httpdigestandroid.DigestConstants.URI;
import static com.android.kj.httpdigestandroid.DigestConstants.USER_NAME;
import static com.android.kj.httpdigestandroid.DigestConstants.WHITE_SPACE;

public class HTTPDigest {
    private Client mClient;
    private WWWAuthenticate mChallenge;
    private Authorization mAuth;
    private byte[] mBody;
    private String mForceCnonce;

    public HTTPDigest(Client client, WWWAuthenticate challenge) {
        this.mClient = client;
        this.mChallenge = challenge;
    }

    public void setBody(byte[] body) {
        this.mBody = body;
    }

    public String getAuthHeader() {
        if (mAuth == null) {
            buildAuth();
        }

        return generateHeaderString();
    }

    private void buildAuth() {
        mAuth = new Authorization();

        defineUserName();
        defineAlgorithm();
        try {
            defineUri();
        } catch (MalformedURLException | IndexOutOfBoundsException e) {
            e.printStackTrace();
            return;
        }
        defineQop();
        generateCnonce();
        generateResponse();
    }

    private void defineUserName() {
        if (TRUE.equals(mChallenge.getUserHash())) {
            mAuth.setUserName(
                    getHash((mClient.getUserName() + COLON + mChallenge.getRealm()).getBytes()));
            mAuth.setUserHash(TRUE);
        } else {
            mAuth.setUserName(mClient.getUserName());
        }
    }

    private void defineAlgorithm() {
        String algorithm = mChallenge.getAlgorithm();
        if (algorithm == null) {
            mAuth.setAlgorithm(ALGORITHM_MD5);
            return;
        }

        mAuth.setAlgorithm(algorithm);
    }

    private String getHash(byte[] src) {
        String hash = null;

        try {
            MessageDigest digest =
                    MessageDigest.getInstance(
                            mAuth.getAlgorithm().replace(ALGORITHM_SESSION_VARIANT, ""));

            digest.update(src);
            byte byteData[] = digest.digest();
            StringBuilder hexStr = new StringBuilder();
            for (byte b : byteData) {
                hexStr.append(String.format("%02x", b));
            }
            hash = hexStr.toString();

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        return hash;
    }

    private void defineUri() throws MalformedURLException, IndexOutOfBoundsException {
        URL url = new URL(mClient.getRequestUrl());
        String authority = url.getAuthority();
        String uri = url.toString();
        uri = uri.substring(uri.indexOf(authority) + authority.length());
        mAuth.setUri(uri);
    }

    private void defineQop() {
        String qop = mChallenge.getQop();
        int indexOfComma = qop.trim().indexOf(COMMA);
        if (indexOfComma > -1) {
            qop = qop.trim().substring(0, indexOfComma);
        }
        mAuth.setQop(qop);
    }

    private void generateCnonce() {
        if (mForceCnonce != null) {
            mAuth.setCNonce(mForceCnonce);
            Authorization.increaseNC();
            return;
        }

        SecureRandom random = new SecureRandom();
        byte[] bytes = new byte[64];
        random.nextBytes(bytes);
        mAuth.setCNonce(Base64.getEncoder().encodeToString(bytes));
        Authorization.increaseNC();
    }

    private void generateResponse() {
        String A1 = generateA1();
        String A2 = generateA2();

        mAuth.setResponse(getKeyedDigest(getHash(A1.getBytes()), getHash(A2.getBytes())));
    }

    private String generateA1() {
        String a1 =
                String.join(
                        COLON, mClient.getUserName(), mChallenge.getRealm(), mClient.getPassword());

        if (mAuth.getAlgorithm().endsWith(ALGORITHM_SESSION_VARIANT)) {
            a1 =
                    String.join(
                            COLON,
                            getHash(a1.getBytes()),
                            mChallenge.getNonce(),
                            mAuth.getCNonce());
        }

        return a1;
    }

    private String generateA2() {
        String a2 = mClient.getRequestMethod() + COLON + mAuth.getUri();

        if (mChallenge.getQop().equals(QOP_AUTH_INTEGRATION)) {
            a2 = a2 + COLON + getHash(mBody);
        }

        return a2;
    }

    private String getKeyedDigest(String H1, String H2) {
        String secret = H1;
        String data =
                String.join(
                        COLON,
                        mChallenge.getNonce(),
                        mAuth.getNC(),
                        mAuth.getCNonce(),
                        mAuth.getQop(),
                        H2);
        return getHash((secret + COLON + data).getBytes());
    }

    private String generateHeaderString() {

        return TYPICAL_DIGEST_TOKEN
                + WHITE_SPACE
                + USER_NAME
                + EQUALS
                + DOUBLE_QUOTATION
                + mAuth.getUserName()
                + DOUBLE_QUOTATION
                + COMMA
                + REALM
                + EQUALS
                + DOUBLE_QUOTATION
                + mChallenge.getRealm()
                + DOUBLE_QUOTATION
                + COMMA
                + URI
                + EQUALS
                + DOUBLE_QUOTATION
                + mAuth.getUri()
                + DOUBLE_QUOTATION
                + COMMA
                + ALGORITHM
                + EQUALS
                + mChallenge.getAlgorithm()
                + COMMA
                + NONCE
                + EQUALS
                + DOUBLE_QUOTATION
                + mChallenge.getNonce()
                + DOUBLE_QUOTATION
                + COMMA
                + NC
                + EQUALS
                + mAuth.getNC()
                + COMMA
                + CNONCE
                + EQUALS
                + DOUBLE_QUOTATION
                + mAuth.getCNonce()
                + DOUBLE_QUOTATION
                + COMMA
                + QOP
                + EQUALS
                + mAuth.getQop()
                + COMMA
                + RESPONSE
                + EQUALS
                + DOUBLE_QUOTATION
                + mAuth.getResponse()
                + DOUBLE_QUOTATION
                + COMMA
                + OPAQUE
                + EQUALS
                + DOUBLE_QUOTATION
                + mChallenge.getOpaque()
                + DOUBLE_QUOTATION
                + (mAuth.getUserHash() == null ? "" : mAuth.getUserHash());
    }

    public void forceCnonceForTest(String n) {
        mForceCnonce = n;
    }
}
