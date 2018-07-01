package com.android.kj.httpdigestandroid;

public class Client {
    private String mUserName;
    private String mPassword;
    private String mRequestUrl;
    private String mRequestMethod;

    public Client(String userName, String password, String requestUrl, String requestMethod) {
        this.mUserName = userName;
        this.mPassword = password;
        this.mRequestUrl = requestUrl;
        this.mRequestMethod = requestMethod;
    }

    public String getUserName() {
        return mUserName;
    }

    public String getPassword() {
        return mPassword;
    }

    public String getRequestUrl() {
        return mRequestUrl;
    }

    public String getRequestMethod() {
        return mRequestMethod;
    }
}
