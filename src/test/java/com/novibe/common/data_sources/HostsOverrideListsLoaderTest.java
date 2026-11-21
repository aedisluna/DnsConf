package com.novibe.common.data_sources;

import com.novibe.common.base_structures.BypassRoute;
import com.novibe.common.base_structures.HostsLine;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;

class HostsOverrideListsLoaderTest {

    @Test
    void alignsOnlyAdvertisedAlternativesAndKeepsFirstSourcePriority() {
        HostsOverrideListsLoader loader = loader(List.of(
                List.of(new HostsLine("192.0.2.2", "api.example.com"),
                        new HostsLine("192.0.2.1", "api.example.com"),
                        new HostsLine("192.0.2.1", "example.com"),
                        new HostsLine("192.0.2.3", "other.example.com")),
                List.of(new HostsLine("192.0.2.1", "other.example.com"))));

        Map<String, BypassRoute> routes = loader.fetchNextDnsWebsites(List.of()).stream()
                .collect(Collectors.toMap(BypassRoute::website, Function.identity()));

        assertEquals(3, routes.size());
        assertEquals("192.0.2.1", routes.get("api.example.com").ip());
        assertEquals("192.0.2.3", routes.get("other.example.com").ip());
    }

    @Test
    void ordinaryLoaderKeepsOriginalFirstIpBehavior() {
        HostsOverrideListsLoader loader = loader(List.of(List.of(
                new HostsLine("192.0.2.2", "api.example.com"),
                new HostsLine("192.0.2.1", "api.example.com"),
                new HostsLine("192.0.2.1", "example.com"))));

        assertEquals("192.0.2.2", loader.fetchWebsites(List.of()).getFirst().ip());
    }

    @Test
    void doesNotInheritAnIpThroughAnInterveningDifferentParent() {
        HostsOverrideListsLoader loader = loader(List.of(List.of(
                new HostsLine("192.0.2.1", "example.com"),
                new HostsLine("192.0.2.2", "other.example.com"),
                new HostsLine("192.0.2.3", "api.other.example.com"),
                new HostsLine("192.0.2.1", "api.other.example.com"))));

        assertEquals("192.0.2.3", loader.fetchNextDnsWebsites(List.of()).getLast().ip());
    }

    private static HostsOverrideListsLoader loader(List<List<HostsLine>> sources) {
        return new HostsOverrideListsLoader() {
            @Override
            protected List<List<HostsLine>> fetchHostsLines(List<String> urls) {
                return sources;
            }
        };
    }
}
