package com.android.kj.httpdigestandroid;

public class Authorization {
    private static int mNC = 0x0;
    private String mUserName;
    private String mUserNameExt; // not supported; no extended notation but hash
    private String mAlgorithm;
    private String mUri;
    private String mQop;
    private String mCNonce;
    private String mUserHash;
    private String mResponse;

    public String getResponse() {
        return mResponse;
    }

    public void setResponse(String response) {
        mResponse = response;
    }

    public String getUserName() {
        return mUserName;
    }

    public void setUserName(String userName) {
        mUserName = userName;
    }

    public String getAlgorithm() {
        return mAlgorithm;
    }

    public void setAlgorithm(String algorithm) {
        mAlgorithm = algorithm;
    }

    public String getUri() {
        return mUri;
    }

    public void setUri(String uri) {
        mUri = uri;
    }

    public String getQop() {
        return mQop;
    }

    public void setQop(String qop) {
        mQop = qop;
    }

    public String getCNonce() {
        return mCNonce;
    }

    public void setCNonce(String CNonce) {
        mCNonce = CNonce;
    }

    public String getNC() {
        return String.format("%08x", mNC);
    }

    public static void increaseNC() {
        mNC++;
    }

    public String getUserHash() {
        return mUserHash;
    }

    public void setUserHash(String userHash) {
        mUserHash = userHash;
    }

    public String toString() {
        return null;
    }
}
