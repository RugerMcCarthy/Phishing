package com.wangdian.birtweb.listener;

public interface EngineDataRequestListener {
    void onSuccess(String data) throws Exception;
    void onFailure();
}
