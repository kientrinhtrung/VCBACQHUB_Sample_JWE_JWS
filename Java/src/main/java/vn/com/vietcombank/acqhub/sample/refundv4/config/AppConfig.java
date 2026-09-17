package vn.com.vietcombank.acqhub.sample.refundv4.config;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Properties;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Doc application.properties (classpath) va ho tro placeholder dang ${key}
 * de tranh lap lai vcb.baseUrl o nhieu dong.
 */
public final class AppConfig {

    private static final Pattern PLACEHOLDER = Pattern.compile("\\$\\{([^}]+)}");

    private final Properties props = new Properties();

    public AppConfig() {
        this("application.properties");
    }

    public AppConfig(String resourceName) {
        try (InputStream in = AppConfig.class.getClassLoader().getResourceAsStream(resourceName)) {
            if (in == null) {
                throw new IllegalStateException("Khong tim thay " + resourceName + " tren classpath");
            }
            props.load(in);
        } catch (IOException e) {
            throw new IllegalStateException("Khong doc duoc " + resourceName, e);
        }
        resolvePlaceholders();
    }

    private void resolvePlaceholders() {
        for (String key : props.stringPropertyNames()) {
            props.setProperty(key, resolve(props.getProperty(key), 0));
        }
    }

    private String resolve(String value, int depth) {
        if (depth > 10) {
            return value;
        }
        Matcher m = PLACEHOLDER.matcher(value);
        StringBuilder sb = new StringBuilder();
        boolean found = false;
        while (m.find()) {
            found = true;
            String refKey = m.group(1);
            String refValue = props.getProperty(refKey, "");
            m.appendReplacement(sb, Matcher.quoteReplacement(refValue));
        }
        m.appendTail(sb);
        String result = sb.toString();
        return found ? resolve(result, depth + 1) : result;
    }

    public String get(String key) {
        String value = props.getProperty(key);
        if (value == null) {
            throw new IllegalStateException("Thieu cau hinh: " + key);
        }
        return value;
    }

    public String get(String key, String defaultValue) {
        return props.getProperty(key, defaultValue);
    }

    public int getInt(String key) {
        return Integer.parseInt(get(key));
    }

    /**
     * Duong dan trong file properties la relative to thu muc chay ung dung (working dir).
     */
    public Path resolvePath(String key) {
        return Path.of(get(key));
    }

    public byte[] readFile(String key) {
        try {
            return Files.readAllBytes(resolvePath(key));
        } catch (IOException e) {
            throw new IllegalStateException("Khong doc duoc file cau hinh cho key '" + key + "': " + get(key), e);
        }
    }
}
