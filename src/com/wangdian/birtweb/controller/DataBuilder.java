package com.wangdian.birtweb.controller;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.SimpleDateFormat;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.Map.Entry;

/**
 * @author xiongying
 */
public class DataBuilder {
    private static final String HOST = "http://sv2.asec.buptnsrc.com:9002";
    private static final String TOKEN_KEY = "testtest";
    private List<Double> codeSimilarity;

    public static void main(String[] args) throws IOException {
        List<String> testHashes = new ArrayList<>();
        testHashes.add("7863d700388653455cd78fdbeab7edfe8df733b1fe915c455729c4a5fdbd5ee4");
        DataBuilder dataBuilder = new DataBuilder();

        try (BufferedWriter bw = new BufferedWriter(new FileWriter("json.txt"))) {
            bw.write(dataBuilder.build(testHashes));
        }
    }

    private static String readAll(Reader rd) throws IOException {
        StringBuilder sb = new StringBuilder();
        int cp;
        while ((cp = rd.read()) != -1) {
            sb.append((char) cp);
        }
        return sb.toString();
    }

    private static JSONObject readJsonFromUrl(String url, String requestMethod) throws IOException, JSONException {
        HttpURLConnection connection = (HttpURLConnection) new URL(url).openConnection();
        connection.setRequestMethod(requestMethod);
        InputStream is = connection.getInputStream();
        BufferedReader rd = new BufferedReader(new InputStreamReader(is, Charset.forName("UTF-8")));
        String jsonText = readAll(rd);
        return new JSONObject(jsonText);
    }

    private static String sha(final String strText, final String strType) {
        // 返回值
        String strResult = null;

        // 是否是有效字符串
        if (strText != null && strText.length() > 0) {
            try {
                // sha 加密开始
                MessageDigest messageDigest = MessageDigest.getInstance(strType);
                // 传入要加密的字符串
                messageDigest.update(strText.getBytes());
                // 得到 byte 類型结果
                byte[] byteBuffer = messageDigest.digest();

                // 將 byte 轉換爲 string
                StringBuilder strHexString = new StringBuilder();
                // 遍歷 byte buffer
                for (byte aByteBuffer : byteBuffer) {
                    String hex = Integer.toHexString(0xff & aByteBuffer);
                    if (hex.length() == 1) {
                        strHexString.append('0');
                    }
                    strHexString.append(hex);
                }
                // 得到返回結果
                strResult = strHexString.toString();
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            }
        }

        return strResult;
    }

    String build(List<String> fileHashes) {
        JSONObject data = new JSONObject();
        data.put("category", "待定");
        Calendar cal = Calendar.getInstance();
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd");
        data.put("reportTime", sdf.format(cal.getTime()));
        data.put("summary", "待定");
        JSONArray apps = new JSONArray();
        for (String fileHash : fileHashes) {
            try {
                System.out.println("filehash = " + fileHash);
                apps.put(buildOneApp(fileHash));
            } catch (IOException e) {
                System.err.print("获取信息失败：" + fileHash);
                e.printStackTrace();
            }
        }
        data.put("phishingApps", apps);
        return data.toString();
    }

    private JSONObject buildOneApp(String fileHash) throws IOException {
        final String phishingResultApi = "/getPhishingResultByFileHash";
        String url = HOST + phishingResultApi + "?fileHash=" + fileHash;
        JSONObject response = readJsonFromUrl(url, "POST").getJSONObject("info");
        JSONObject phishingResult = new JSONObject(response.getString("result"));

        String phishingHash = response.getString("fileHash");
        JSONObject phishingInfo = getFileInfoByHash(phishingHash);
        JSONObject phishingCer = new JSONObject(phishingInfo.getString("cerInfo"));

        JSONObject legalResult = findLegalResult(phishingResult);
        String legalHash = legalResult.getString("fileHash");
        JSONObject legalInfo = getFileInfoByHash(legalHash);
        JSONObject legalCer = new JSONObject(legalInfo.getString("cerInfo"));

        JSONArray phishingChannel = getChannelDistribution(phishingInfo);
        JSONArray legalChannel = getChannelDistribution(legalInfo);

        JSONObject result = new JSONObject();

        result.put("appName", phishingInfo.getString("appName"));

        JSONObject basicInfo = new JSONObject();
        basicInfo.put("result", phishingResult.getString("msg"));
        basicInfo.put("appName", phishingInfo.getString("appName"));
        basicInfo.put("MD5", phishingInfo.getString("fileHashMd5"));
        basicInfo.put("SHA1", phishingInfo.getString("fileHashSha1"));
        basicInfo.put("SHA256", phishingInfo.getString("fileHashSha256"));
        basicInfo.put("fileSize", phishingInfo.getString("fileSize"));
        basicInfo.put("version", phishingInfo.getString("versionName"));
        basicInfo.put("isJiaGu", phishingInfo.getInt("packerFlag") == 0 ? "否" : "是");
        basicInfo.put("jiaGuCategory", phishingInfo.getString("packerName"));

        JSONObject phishingApp = new JSONObject();
        phishingApp.put("img", phishingInfo.getString("logo"));
        phishingApp.put("appName", phishingInfo.getString("appName"));
        phishingApp.put("packageName", phishingInfo.getString("packageName"));
        phishingApp.put("version", phishingInfo.getString("versionName"));
        phishingApp.put("newPriority", legalResult.has("detectionAppAddSensitivePermission") ? legalResult.get("detectionAppAddSensitivePermission") : null);
        phishingApp.put("cerHash", phishingInfo.getString("cerMd5"));
        phishingApp.put("cerOwner", phishingCer.getString("owner"));
        phishingApp.put("certifiedTime", getDateTimeFromCer(phishingCer.getString("valid_from")));
        phishingApp.put("cerSerialNum", phishingCer.getString("serial_number"));

        JSONObject legalApp = new JSONObject();
        legalApp.put("img", legalInfo.getString("logo"));
        legalApp.put("appName", legalInfo.getString("appName"));
        legalApp.put("packageName", legalInfo.getString("packageName"));
        legalApp.put("version", legalInfo.getString("versionName"));
        legalApp.put("newPriority", legalResult.has("detectionAppAddSensitivePermission") ? legalResult.get("detectionAppAddSensitivePermission") : null);
        legalApp.put("cerHash", legalInfo.getString("cerMd5"));
        legalApp.put("cerOwner", legalCer.getString("owner"));
        legalApp.put("certifiedTime", getDateTimeFromCer(legalCer.getString("valid_from")));
        legalApp.put("cerSerialNum", legalCer.getString("serial_number"));

        JSONObject similarities = new JSONObject();
        if (phishingResult.getJSONObject("legalApp").get("similarLogoGrade") == null || phishingResult.getJSONObject("legalApp").get("similarLogoGrade").equals(null)) {
            similarities.put("imgSimilar", 0);
        } else {
            similarities.put("imgSimilar",
                    round(phishingResult.getJSONObject("legalApp").getDouble("similarLogoGrade"), 4));
        }
        if (phishingResult.getJSONObject("legalApp").get("similarNameGrade") == null || phishingResult.getJSONObject("legalApp").get("similarNameGrade").equals(null)) {
            similarities.put("appNameSimilar", 0);
        } else {
            similarities.put("appNameSimilar",
                    round(phishingResult.getJSONObject("legalApp").getDouble("similarNameGrade"), 4));
        }
        if (phishingResult.getJSONObject("legalApp").get("similarPackageNameGrade") == null || phishingResult.getJSONObject("legalApp").get("similarPackageNameGrade").equals(null)) {
            similarities.put("packageNameSimilar", 0);
        } else {
            similarities.put("packageNameSimilar",
                    round(phishingResult.getJSONObject("legalApp").getDouble("similarPackageNameGrade"), 4));
        }
        similarities.put("codeSimilar", getCodeSim());

        JSONObject diffInfo = new JSONObject();
        diffInfo.put("similars", similarities);
        diffInfo.put("legalApp", legalApp);
        diffInfo.put("phishingApp", phishingApp);

        JSONObject channelDistribution = new JSONObject();
        channelDistribution.put("phishingChannel", phishingChannel);
        channelDistribution.put("legalChannel", legalChannel);

        result.put("basicInfo", basicInfo);
        result.put("diffInfo", diffInfo);
        result.put("channelDistribution", channelDistribution);

        return result;
    }

    private Double getCodeSim() {
        Double result = 0.0;
        if (codeSimilarity != null && codeSimilarity.size() > 0) {
            result = codeSimilarity.get(0);
            codeSimilarity.remove(0);
        }
        return result;
    }

    private String getDateTimeFromCer(String s) {
        DateTimeFormatter dateTimeFormatter = DateTimeFormatter.ofPattern("EEE MMM dd HH:mm:ss OOOO yyyy");
        LocalDateTime zonedDateTime = LocalDateTime.parse(s, dateTimeFormatter);
        DateTimeFormatter outFormatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
        return zonedDateTime.format(outFormatter);
    }

    private double round(double v, int i) {
        return Math.round(v * Math.pow(10, i)) / Math.pow(10, i);
    }

    private JSONArray getChannelDistribution(JSONObject fileInfo) throws IOException {
        String asecAppApi = "/api/getAsecAppByPackageNameAndCerHash";
        Map<String, String> params = new HashMap<>(16);
        params.put("packageName", fileInfo.getString("packageName"));
        params.put("cerHash", fileInfo.getString("cerMd5"));
        String token = getToken(params);
        String appUrl = HOST + asecAppApi + "?packageName=" + fileInfo.getString("packageName") + "&cerHash=" + fileInfo
                .getString("cerMd5") + "&token=" + token;
        JSONArray response = readJsonFromUrl(appUrl, "POST").getJSONArray("info");
        List<JSONObject> result = new ArrayList<>();
        if (response.toString().isEmpty()) {
            return new JSONArray(result);
        }
        for (int i = 0; i < response.length(); i++) {
            String appId = response.getJSONObject(i).getString("appId");
            String channelListApi = "/api/getAllAppChannelListByAppId";
            params.clear();
            params.put("appId", appId);
            token = getToken(params);
            String channelUrl = HOST + channelListApi + "?appId=" + appId + "&token=" + token;
            JSONArray channels = readJsonFromUrl(channelUrl, "POST").getJSONArray("info");
            for (int j = 0; j < channels.length(); j++) {
                JSONObject channel = channels.getJSONObject(j);
                JSONObject channelInfo = new JSONObject();
                channelInfo.put("appStore", getChannelName(channel.getString("appChannelId")));
                channelInfo.put("crawlerTime", getTimeFromTimestamp(channel.getLong("appTsCrawl")));
                channelInfo.put("detailUrl", channel.getString("appUrlMeta"));
                channelInfo.put("downloadUrl", channel.getString("appUrlDownload"));
                result.add(channelInfo);
            }
        }
        result.sort((o1, o2) -> {
            String key1 = sha(o1.getString("appStore"), "MD5") + o1.getString("crawlerTime");
            String key2 = sha(o2.getString("appStore"), "MD5") + o2.getString("crawlerTime");
            return -key1.compareTo(key2);
        });
        Set<String> seen = new HashSet<>();
        JSONArray res = new JSONArray();
        for (JSONObject channelInfo : result) {
            String key = channelInfo.getString("detailUrl");
            if (seen.contains(key)) {
                continue;
            }
            res.put(channelInfo);
            seen.add(key);
        }
        return res;
    }

    private String getTimeFromTimestamp(long appTsCrawl) {
        LocalDateTime localDateTime = LocalDateTime.ofInstant(Instant.ofEpochMilli(appTsCrawl),
                TimeZone.getDefault().toZoneId());
        DateTimeFormatter dateTimeFormatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
        return localDateTime.format(dateTimeFormatter);
    }

    private String getChannelName(String appChannelId) throws IOException {
        String channelNameApi = "/getChannelInfoByChannelId";
        String url = HOST + channelNameApi + "?channelId=" + appChannelId;
        JSONObject response = new JSONObject();
        try {
            response = readJsonFromUrl(url, "GET").getJSONObject("info");
            return response.getString("channelName");
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("channelId=" + appChannelId + "  response = " + response);
            return "unknown";
        }
    }

    private String getToken(Map<String, String> params) {
        StringBuilder sb = new StringBuilder();
        List<String> keys = new ArrayList<>();
        Set<Entry<String, String>> entries = params.entrySet();
        for (Map.Entry<String, String> entry : entries) {
            keys.add(entry.getKey());
        }
        //key排序
        Collections.sort(keys);
        //拼接参数
        for (String s : keys) {
            sb.append(s).append("=").append(params.get(s));
        }
        // 在请求参数字符串末尾拼接上 secure_key
        sb.append(TOKEN_KEY);
        String signString = sb.toString();
        //计算md5
        return sha(signString, "MD5");
    }

    private JSONObject findLegalResult(JSONObject phishingResult) {
        try {
            JSONObject legalApp = phishingResult.getJSONObject("legalApp");
            double maxLogoGrade = 0;
            Object o = legalApp.get("similarLogoGrade");
            if (o == null || o.equals(null)) {
                System.out.println("对象为空");
            }
            if (legalApp.has("similarLogoGrade")) {
                Object similarLogoGradeObject = legalApp.get("similarLogoGrade");
                if (similarLogoGradeObject == null || o.equals(null)) {
                    maxLogoGrade = 0;
                } else {
                    maxLogoGrade = legalApp.getDouble("similarLogoGrade");
                }
            }
            JSONArray infos = legalApp.getJSONArray("legalApkInfos");
            for (int i = 0; i < infos.length(); i++) {
                JSONObject info = infos.getJSONObject(i);
                if (info.has("similarLogoGrade") && info.get("similarLogoGrade") != null && !legalApp.get("similarLogoGrade").equals(null) && info.getDouble("similarLogoGrade") == maxLogoGrade) {
                    return info;
                }
            }
            return infos.getJSONObject(0);
        } catch (JSONException e) {
            e.printStackTrace();
            System.out.println("phishingResult = " + phishingResult);
            return null;
        }
    }

    private JSONObject getFileInfoByHash(String fileHash) throws IOException {
        String fileInfoApi = "/getApkInfoByFileHash";
        String url = HOST + fileInfoApi + "?fileHash=" + fileHash;
        return readJsonFromUrl(url, "POST").getJSONObject("info");
    }
}
