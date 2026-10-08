package org.reachability.analyzer.engine;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/** A13: {@code class#method} token lists into the interface → callback methods map. */
public final class CallbackInterfaceSpecs {

    private CallbackInterfaceSpecs() {
    }

    public static Map<String, List<String>> parse(List<String> raw) {
        Map<String, List<String>> result = new TreeMap<>();
        if (raw == null) {
            return result;
        }
        for (String entry : raw) {
            int hash = entry.indexOf('#');
            if (hash <= 0 || hash == entry.length() - 1) {
                continue;
            }
            result.computeIfAbsent(entry.substring(0, hash), key -> new ArrayList<>())
                    .add(entry.substring(hash + 1));
        }
        return result;
    }
}
