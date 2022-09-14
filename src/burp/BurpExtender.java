package burp;

import java.io.PrintWriter;
import java.util.List;
import java.util.Arrays;

public class BurpExtender implements IBurpExtender, IHttpListener, IProxyListener {

    private static final String SPLIT_STRING = ".vhost-proxy.";
    private IExtensionHelpers helpers;
    private PrintWriter stdout;
    private IBurpExtenderCallbacks callbacks;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        // set our extension name
        this.callbacks = callbacks;
        callbacks.setExtensionName("VirtualHost Proxy");
        this.stdout = new PrintWriter(callbacks.getStdout(), true);
        this.helpers = callbacks.getHelpers();
        callbacks.registerHttpListener(this);

    }

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        // only process requests

        // stdout.println(
        // (messageIsRequest ? "HTTP request to " : "HTTP response from ") +
        // messageInfo.getHttpService() +
        // " [" + callbacks.getToolName(toolFlag) + "]");
        if (messageIsRequest) {
            // get the HTTP service for the request
            IHttpService httpService = messageInfo.getHttpService();

            // if the host is HOST_FROM, change it to HOST_TO
            if (httpService.getHost().contains(SPLIT_STRING)) {
                String[] arrOfStr = httpService.getHost().split(SPLIT_STRING, 3);
                String ORIGINAL_HOST = httpService.getHost();
                String HOST = arrOfStr[0];
                String VHOST = arrOfStr[1];

                messageInfo.setHttpService(helpers.buildHttpService(
                        HOST, httpService.getPort(), httpService.getProtocol()));

                byte[] req = messageInfo.getRequest();
                IRequestInfo parsed = this.helpers.analyzeRequest(req);
                // String req_str = this.helpers.bytesToString(req);
                byte[] body = Arrays.copyOfRange(req, parsed.getBodyOffset(), req.length);
                List<String> headers = parsed.getHeaders();
                String bad_header = "";
                for (String header : headers) {
                    if (header.startsWith("Host: ")) {
                        bad_header = header;
                    }
                }
                headers.remove(bad_header);
                headers.add("Host: " + VHOST);
                byte[] httpRequest = this.helpers.buildHttpMessage(headers, body);
                messageInfo.setRequest(httpRequest);

                stdout.println("Host: " + messageInfo.getHttpService().getHost());
                messageInfo.setComment(ORIGINAL_HOST);

                // stdout.println(headers);
            }

        } else {
            String ORIGINAL_HOST = messageInfo.getComment();

            if (ORIGINAL_HOST != null && ORIGINAL_HOST.contains(SPLIT_STRING)) {
                stdout.println("Got comment: " + messageInfo.getComment());

                String[] arrOfStr = ORIGINAL_HOST.split(SPLIT_STRING, 3);

                String VHOST = arrOfStr[1];

                byte[] req = messageInfo.getRequest();
                IRequestInfo parsed = this.helpers.analyzeRequest(req);

                String req_str = this.helpers.bytesToString(req);
                String body = req_str.substring(parsed.getBodyOffset()).replace("://" + VHOST, "://" + ORIGINAL_HOST);

                List<String> headers = parsed.getHeaders();
                byte[] httpRequest = this.helpers.buildHttpMessage(headers, body.getBytes());
                messageInfo.setRequest(httpRequest);
            }

        }
    }

    @Override
    public void processProxyMessage(boolean messageIsRequest, IInterceptedProxyMessage message) {
        stdout.println(
                (messageIsRequest ? "Proxy request to " : "Proxy response from ") +
                        message.getMessageInfo().getHttpService());
    }
}