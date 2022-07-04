package com.jisu.securityproject.util;

import javax.servlet.http.HttpServletRequest;

public class WebUtil {
    private static final String XML_HTTP_REQUEST = "XMLHttpRequest";
    private static final String X_REQUESTED_WITH = "X-Requested-With";

    private static final String CONTENT_TYPE = "Content-type";
    private static final String CONTENT_TYPE_JSON = "application/json";

    /**
     * 사용자가 요청할때 헤더에 정보를 보내는데 그 정보에 담김 값이 같은지, 그 값은서버에서 미리 정해둔다.
     * @param request
     * @return
     */
    public static boolean isAjax(HttpServletRequest request) {
        return XML_HTTP_REQUEST.equals(request.getHeader(X_REQUESTED_WITH));
    }

    public static boolean isContentTypeJson(HttpServletRequest request) {
        return request.getHeader(CONTENT_TYPE).contains(CONTENT_TYPE_JSON);
    }
}
