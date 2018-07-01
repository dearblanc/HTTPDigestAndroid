package com.android.kj.httpdigestandroid;

import android.text.TextUtils;

import java.util.StringTokenizer;

import static com.android.kj.httpdigestandroid.DigestConstants.ALGORITHM;
import static com.android.kj.httpdigestandroid.DigestConstants.ALGORITHM_MD5;
import static com.android.kj.httpdigestandroid.DigestConstants.ALGORITHM_SESSION_VARIANT;
import static com.android.kj.httpdigestandroid.DigestConstants.ALGORITHM_SHA256;
import static com.android.kj.httpdigestandroid.DigestConstants.CHARSET;
import static com.android.kj.httpdigestandroid.DigestConstants.COMMA;
import static com.android.kj.httpdigestandroid.DigestConstants.DOMAIN;
import static com.android.kj.httpdigestandroid.DigestConstants.DOUBLE_QUOTATION;
import static com.android.kj.httpdigestandroid.DigestConstants.EQUALS;
import static com.android.kj.httpdigestandroid.DigestConstants.ESCAPE;
import static com.android.kj.httpdigestandroid.DigestConstants.LOWER_CASE_DIGEST;
import static com.android.kj.httpdigestandroid.DigestConstants.NONCE;
import static com.android.kj.httpdigestandroid.DigestConstants.OPAQUE;
import static com.android.kj.httpdigestandroid.DigestConstants.QOP;
import static com.android.kj.httpdigestandroid.DigestConstants.REALM;
import static com.android.kj.httpdigestandroid.DigestConstants.STALE;
import static com.android.kj.httpdigestandroid.DigestConstants.USERHASH;

public class WWWAuthenticate {
    private String mRealm;
    private String mDomains;
    private String mNonce;
    private String mOpaque;
    private String mStale;
    private String mAlgorithm;
    private String mQop;
    private String mCharSet;
    private String mUserHash;

    public static WWWAuthenticate parseHeader(String headerWWWAuth) {
        WWWAuthenticate auth = new WWWAuthenticate();
        auth.parse(headerWWWAuth);

        return auth;
    }

    private WWWAuthenticate() {}

    public String getRealm() {
        return mRealm;
    }

    private void setRealm(String realm) {
        mRealm = realm;
    }

    public String getDomains() {
        return mDomains;
    }

    private void setDomains(String domains) {
        mDomains = domains;
    }

    public String getNonce() {
        return mNonce;
    }

    private void setNonce(String nonce) {
        mNonce = nonce;
    }

    public String getOpaque() {
        return mOpaque;
    }

    private void setOpaque(String opaque) {
        mOpaque = opaque;
    }

    public String getStale() {
        return mStale;
    }

    private void setStale(String stale) {
        mStale = stale;
    }

    public String getAlgorithm() {
        return mAlgorithm;
    }

    private void setAlgorithm(String algorithm) {
        mAlgorithm = algorithm;
    }

    public String getQop() {
        return mQop;
    }

    private void setQop(String qop) {
        mQop = qop;
    }

    public String getCharSet() {
        return mCharSet;
    }

    private void setCharSet(String charSet) {
        mCharSet = charSet;
    }

    public String getUserHash() {
        return mUserHash;
    }

    private void setUserHash(String userHash) {
        mUserHash = userHash;
    }

    private void parse(String challenge) {
        if (!isDigestScheme(challenge)) {
            return;
        }

        parseMultipleValueParam(challenge);

        int indexOfRealm = challenge.toLowerCase().indexOf(REALM);
        if (indexOfRealm < 0) {
            return;
        }

        StringTokenizer tokenizer = new StringTokenizer(challenge.substring(indexOfRealm), COMMA);
        while (tokenizer.hasMoreTokens()) {
            parseParameter(tokenizer.nextToken());
        }
    }

    private boolean isDigestScheme(String header) {
        return header.toLowerCase().startsWith(LOWER_CASE_DIGEST);
    }

    private void parseMultipleValueParam(String headerValue) {
        parseLWSSeparatedParam(headerValue);
        parseCommaSeparatedParam(headerValue);
    }

    private void parseLWSSeparatedParam(String header) {
        String lowercaseHeader = header.toLowerCase();
        int startKeyIndex = lowercaseHeader.indexOf(DOMAIN + EQUALS);
        if (startKeyIndex < 0) {
            return;
        }
        int startValueIndex = lowercaseHeader.indexOf(DOUBLE_QUOTATION, startKeyIndex);
        int endValueIndex = lowercaseHeader.indexOf(DOUBLE_QUOTATION, startValueIndex + 1);
        if (startValueIndex < 0 || endValueIndex < 0) {
            return;
        }
        try {
            setDomains(header.substring(startKeyIndex + 1, endValueIndex));
        } catch (IndexOutOfBoundsException e) {
            e.printStackTrace();
        }
    }

    private void parseCommaSeparatedParam(String header) {
        String lowercaseHeader = header.toLowerCase();
        String keyword = QOP + EQUALS;
        int startKeyIndex = lowercaseHeader.indexOf(keyword);
        if (startKeyIndex < 0) {
            return;
        }
        int startValueIndex =
                lowercaseHeader.indexOf(DOUBLE_QUOTATION, startKeyIndex + keyword.length());
        int endValueIndex = lowercaseHeader.indexOf(DOUBLE_QUOTATION, startValueIndex + 1);
        if (startValueIndex < 0 || endValueIndex < 0) {
            return;
        }
        try {
            setQop(header.substring(startValueIndex + 1, endValueIndex));
        } catch (IndexOutOfBoundsException e) {
            e.printStackTrace();
        }
    }

    private String removeWhiteSpace(String headerValue) {
        return headerValue.replace(" ", "");
    }

    private void parseParameter(String param) {
        int indexOfEquals = param.indexOf(EQUALS);
        if (indexOfEquals < 0) {
            return;
        }

        String key = null;
        String val = null;
        try {
            key = param.substring(0, indexOfEquals).toLowerCase();
            val = param.substring(indexOfEquals + 1);
        } catch (IndexOutOfBoundsException e) {
            e.printStackTrace();
        }

        if (TextUtils.isEmpty(key) || TextUtils.isEmpty(val)) {
            return;
        }

        try {
            val = removeQuotation(val);
        } catch (IndexOutOfBoundsException e) {
            e.printStackTrace();
            return;
        }

        if (key.equals(NONCE)) {
            parseNonce(val);
            return;
        }
        setParam(key, val);
    }

    private void parseNonce(String val) {
        val.replaceAll(ESCAPE + DOUBLE_QUOTATION, DOUBLE_QUOTATION);
        setNonce(val);
    }

    private void setParam(String key, String val) {
        if (key.equals(REALM)) {
            setRealm(val);
        } else if (key.equals(OPAQUE)) {
            setOpaque(val);
        } else if (key.equals(STALE)) {
            setStale(val);
        } else if (key.equals(ALGORITHM)) {
            setAlgorithm(val);
        } else if (key.equals(CHARSET)) {
            setCharSet(val);
        } else if (key.equals(USERHASH)) {
            setUserHash(val);
        } else {
            // UNKNOWN PARAMETER
        }
    }

    private String removeQuotation(String val) throws IndexOutOfBoundsException {
        if (val.charAt(0) == '"') {
            val = val.substring(1);
        }
        if (val.charAt(val.length() - 1) == '"') {
            val = val.substring(0, val.length() - 1);
        }

        return val;
    }

    public boolean validAlgorithm(String algorithm) {
        String lowercaseAlgorithm = algorithm.toLowerCase();

        return ALGORITHM_MD5.equals(lowercaseAlgorithm)
                || (ALGORITHM_MD5 + ALGORITHM_SESSION_VARIANT).equals(lowercaseAlgorithm)
                || ALGORITHM_SHA256.equals(lowercaseAlgorithm)
                || (ALGORITHM_SHA256 + ALGORITHM_SESSION_VARIANT).equals(lowercaseAlgorithm);
        // || ALGORITHM_SHA512_256.equals(lowercaseAlgorithm)
        // || (ALGORITHM_SHA512_256 + ALGORITHM_SESSION_VARIANT).equals(lowercaseAlgorithm);
    }
}
