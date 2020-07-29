package com.wangdian.birtweb.controller;

import io.reactivex.Observable;
import org.json.JSONObject;
import retrofit2.http.GET;
import retrofit2.http.Query;

public interface ParseAPKService {
    @GET("getPhishingResultByFileHash")
    Observable<JSONObject> parseAPK(@Query("fileHash") String fileHash);
}
