package net.eldiosantos.okhttp.interceptor;

import net.logstash.logback.marker.LogstashMarker;
import net.logstash.logback.marker.Markers;
import okhttp3.*;
import okhttp3.internal.http.HttpHeaders;
import okio.Buffer;
import okio.BufferedSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.EOFException;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.TimeUnit;

public class LogstashLoggingInterceptor implements Interceptor {

    private static final String LOG_MESSAGE = LogstashLoggingInterceptor.class.getSimpleName();

    public static final String KEY_PROTOCOL = "protocol";
    public static final String KEY_METHOD = "method";
    public static final String KEY_URL = "url";
    public static final String KEY_REQUEST_CONTENT_LENGTH = "request.Content-Length";
    public static final String KEY_REQUEST_CONTENT_TYPE = "request.Content-Type";
    public static final String KEY_REQUEST_BODY = "request.body";
    public static final String KEY_RESPONSE_CONTENT_LENGTH = "response.Content-Length";
    public static final String KEY_RESPONSE_CODE = "response.code";
    public static final String KEY_RESPONSE_MESSAGE = "response.message";
    public static final String KEY_DURATION_MS = "duration_ms";
    public static final String KEY_RESPONSE_HEADERS = "response.headers";
    public static final String KEY_RESPONSE_BODY = "response.body";
    private final Logger logger;
    private final Level level;

    public LogstashLoggingInterceptor(Logger logger, Level level) {
        this.logger = logger;
        this.level = level;
    }

    public LogstashLoggingInterceptor(Level level) {
        this.logger = LoggerFactory.getLogger(getClass());
        this.level = level;
    }

    public Response intercept(Chain chain) throws IOException {
        Level level = this.level;

        Request request = chain.request();
        if (level == Level.NONE) {
            return chain.proceed(request);
        }

        boolean logBody = level == Level.BODY;
        boolean logHeaders = logBody || level == Level.HEADERS;

        RequestBody requestBody = request.body();
        boolean hasRequestBody = requestBody != null;

        Connection connection = chain.connection();
        Protocol protocol = connection != null ? connection.protocol() : Protocol.HTTP_1_1;
        final LogstashMarker marker = Markers.append(KEY_PROTOCOL, protocol.toString())
                .and(Markers.append(KEY_METHOD, request.method()))
                .and(Markers.append(KEY_URL, request.url().toString()));

        if (!logHeaders && hasRequestBody) {
            marker.and(Markers.append(KEY_REQUEST_CONTENT_LENGTH, requestBody.contentLength()));

        }

        if (logHeaders) {
            if (hasRequestBody) {
                // Request body headers are only present when installed as a network interceptor. Force
                // them to be included (when available) so there values are known.
                if (requestBody.contentType() != null) {
                    marker.and(Markers.append(KEY_REQUEST_CONTENT_TYPE, requestBody.contentType()));
                }
                if (requestBody.contentLength() != -1) {
                    marker.and(Markers.append(KEY_REQUEST_CONTENT_LENGTH, requestBody.contentLength()));
                }
            }

            Headers headers = request.headers();
            marker.and(Markers.append("request.headers", headers.toMultimap()));

            if (!logBody || !hasRequestBody) {
                marker.and(Markers.append(KEY_REQUEST_BODY, "not logged"));
            } else if (bodyEncoded(request.headers())) {
                marker.and(Markers.append(KEY_REQUEST_BODY, "(encoded body omitted)"));
            } else {
                Buffer buffer = new Buffer();
                requestBody.writeTo(buffer);

                Charset charset = StandardCharsets.UTF_8;
                MediaType contentType = requestBody.contentType();
                if (contentType != null) {
                    charset = contentType.charset(StandardCharsets.UTF_8);
                }

                if (isPlaintext(buffer)) {
                    marker.and(Markers.append(KEY_REQUEST_BODY, buffer.readString(charset)));
                } else {
                    marker.and(Markers.append(KEY_REQUEST_BODY, ("binary byte body omitted")));
                }
            }
        }

        long startNs = System.nanoTime();
        Response response;
        try {
            response = chain.proceed(request);
        } catch (Exception e) {
            marker.and(Markers.append("errorMessage", e.getMessage()));
            logger.error(marker, LOG_MESSAGE, e);
            throw e;
        }
        long tookMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - startNs);

        ResponseBody responseBody = response.body();;
        marker.and(Markers.append(KEY_RESPONSE_CONTENT_LENGTH, responseBody.contentLength()))
            .and(Markers.append(KEY_RESPONSE_CODE, response.code()))
            .and(Markers.append(KEY_RESPONSE_MESSAGE, response.message()))
            .and(Markers.append(KEY_DURATION_MS, tookMs));

        if (logHeaders) {
            Headers headers = response.headers();
            marker.and(Markers.append(KEY_RESPONSE_HEADERS, headers.toMultimap()));

            if (!logBody || !HttpHeaders.hasBody(response)) {
                marker.and(Markers.append(KEY_RESPONSE_BODY, "(omitted)"));
            } else if (bodyEncoded(response.headers())) {
                marker.and(Markers.append(KEY_RESPONSE_BODY, "(encoded body omitted)"));
            } else {
                BufferedSource source = responseBody.source();
                source.request(Long.MAX_VALUE); // Buffer the entire body.
                Buffer buffer = source.buffer();

                Charset charset = StandardCharsets.UTF_8;
                MediaType contentType = responseBody.contentType();
                if (contentType != null) {
                    charset = contentType.charset(StandardCharsets.UTF_8);
                }

                if (!isPlaintext(buffer)) {
                    marker.and(Markers.append(KEY_RESPONSE_BODY, "(binary body omitted)"));
                    return response;
                }

                if (responseBody.contentLength() != 0) {
                    marker.and(Markers.append(KEY_RESPONSE_BODY, buffer.clone().readString(charset)));
                }

                logger.debug(marker, getClass().getSimpleName());
            }
        }

        return response;
    }


    private boolean bodyEncoded(Headers headers) {
        String contentEncoding = headers.get("Content-Encoding");
        return contentEncoding != null && !contentEncoding.equalsIgnoreCase("identity");
    }
    static boolean isPlaintext(Buffer buffer) {
        try {
            Buffer prefix = new Buffer();
            long byteCount = buffer.size() < 64 ? buffer.size() : 64;
            buffer.copyTo(prefix, 0, byteCount);
            for (int i = 0; i < 16; i++) {
                if (prefix.exhausted()) {
                    break;
                }
                int codePoint = prefix.readUtf8CodePoint();
                if (Character.isISOControl(codePoint) && !Character.isWhitespace(codePoint)) {
                    return false;
                }
            }
            return true;
        } catch (EOFException e) {
            return false; // Truncated UTF-8 sequence.
        }
    }

}
