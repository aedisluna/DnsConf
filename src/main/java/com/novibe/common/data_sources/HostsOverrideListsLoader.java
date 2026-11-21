package com.novibe.common.data_sources;

import com.novibe.common.base_structures.BypassRoute;
import com.novibe.common.base_structures.HostsLine;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Predicate;

@Service
public class HostsOverrideListsLoader extends ListLoader<BypassRoute> {

    @Override
    protected String listType() {
        return "Override";
    }

    @Override
    protected Predicate<HostsLine> filterRelatedLines() {
        return line -> line.hasIpAndDomain() && !HostsBlockListsLoader.isBlockIp(line.ip());
    }

    @Override
    protected BypassRoute toObject(HostsLine line) {
        return new BypassRoute(line.ip(), line.domain());
    }

    public List<BypassRoute> fetchNextDnsWebsites(List<String> urls) {
        Map<String, Set<String>> options = new LinkedHashMap<>();
        for (List<HostsLine> source : fetchHostsLines(urls)) {
            Map<String, Set<String>> sourceOptions = new LinkedHashMap<>();
            for (HostsLine line : source) {
                sourceOptions.computeIfAbsent(line.domain(), ignored -> new LinkedHashSet<>()).add(line.ip());
            }
            // Only the first source that contains a domain may choose its proxy.
            sourceOptions.forEach(options::putIfAbsent);
        }

        Map<String, String> selected = new LinkedHashMap<>();
        List<String> domains = new ArrayList<>(options.keySet());
        domains.sort(Comparator.comparingInt(String::length));
        for (String domain : domains) {
            Set<String> allowedIps = options.get(domain);
            String ip = allowedIps.iterator().next();
            String parent = domain;
            while (parent.contains(".")) {
                parent = parent.substring(parent.indexOf('.') + 1);
                if (selected.containsKey(parent)) {
                    if (allowedIps.contains(selected.get(parent))) {
                        ip = selected.get(parent);
                    }
                    break;
                }
            }
            selected.put(domain, ip);
        }
        List<BypassRoute> routes = new ArrayList<>();
        options.keySet().forEach(domain -> routes.add(new BypassRoute(selected.get(domain), domain)));
        return routes;
    }
}
