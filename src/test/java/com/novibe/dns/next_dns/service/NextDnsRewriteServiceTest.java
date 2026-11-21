package com.novibe.dns.next_dns.service;

import com.novibe.common.base_structures.BypassRoute;
import com.novibe.common.data_sources.ExcludeRedirectSettingsLoader;
import com.novibe.common.exception.UserInputException;
import com.novibe.common.service.ExcludeRedirectCheckService;
import com.novibe.dns.next_dns.http.NextDnsRewriteClient;
import com.novibe.dns.next_dns.http.dto.request.CreateRewriteDto;
import com.novibe.dns.next_dns.http.dto.response.rewrite.RewriteDto;
import com.novibe.dns.next_dns.http.dto.response.rewrite.SingleRewriteResponse;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.IntStream;

import static org.junit.jupiter.api.Assertions.*;

class NextDnsRewriteServiceTest {

    @Test
    void compactsInheritedAnswersButKeepsAnInterveningDifferentAnswer() {
        FakeClient client = new FakeClient(List.of());
        NextDnsRewriteService service = service(client);
        List<CreateRewriteDto> pending = service.cleanupOutdatedAndExcluded(requests(
                "example.com", "192.0.2.1",
                "api.example.com", "192.0.2.1",
                "other.example.com", "192.0.2.2",
                "nested.other.example.com", "192.0.2.1"));

        assertEquals(List.of("example.com", "other.example.com", "nested.other.example.com"),
                pending.stream().map(CreateRewriteDto::name).toList());
    }

    @Test
    void refuses500ExistingPlus829NewBeforeChangingAnything() {
        FakeClient client = new FakeClient(existing(500));
        NextDnsRewriteService service = service(client);
        Map<String, CreateRewriteDto> desired = new LinkedHashMap<>();
        IntStream.range(0, 829).forEach(i -> desired.put("new" + i + ".test",
                new CreateRewriteDto("new" + i + ".test", "192.0.2.2")));

        assertThrows(UserInputException.class, () -> service.cleanupOutdatedAndExcluded(desired));
        assertTrue(client.deleted.isEmpty());
        assertEquals(500, client.rows.size());
    }

    @Test
    void refusesOverflowBeforeDeletingAnOutdatedRule() {
        FakeClient client = new FakeClient(existing(500));
        NextDnsRewriteService service = service(client);

        assertThrows(UserInputException.class, () -> service.cleanupOutdatedAndExcluded(requests(
                "old0.test", "192.0.2.2", "new.test", "192.0.2.2")));
        assertTrue(client.deleted.isEmpty());
    }

    @Test
    void removesRedundantExistingChildrenBeforeSavingAtCapacity() {
        List<RewriteDto> existing = new ArrayList<>(existing(499));
        existing.add(new RewriteDto("child", "api.example.com", "192.0.2.1"));
        FakeClient client = new FakeClient(existing);
        NextDnsRewriteService service = service(client);

        List<CreateRewriteDto> pending = service.cleanupOutdatedAndExcluded(requests(
                "example.com", "192.0.2.1", "api.example.com", "192.0.2.1"));
        service.saveRewrites(pending);

        assertEquals(List.of("child"), client.deleted);
        assertEquals(500, client.rows.size());
        assertTrue(client.rows.stream().anyMatch(r -> r.name().equals("example.com")));
        assertTrue(client.rows.stream().anyMatch(r -> r.name().equals("old0.test")));
    }

    @Test
    void preservesUnknownManualRuleAndItsMoreSpecificSourceAnswer() {
        FakeClient client = new FakeClient(List.of(
                new RewriteDto("manual", "private.example.com", "192.0.2.9")));
        NextDnsRewriteService service = service(client);

        List<CreateRewriteDto> pending = service.cleanupOutdatedAndExcluded(requests(
                "example.com", "192.0.2.1",
                "api.private.example.com", "192.0.2.1"));

        assertEquals(2, pending.size());
        assertTrue(client.deleted.isEmpty());
    }

    @Test
    void keepsMatchingAnswerWhenAnotherOldAnswerForSameNameExists() {
        FakeClient client = new FakeClient(List.of(
                new RewriteDto("outdated", "example.com", "192.0.2.2"),
                new RewriteDto("matching", "example.com", "192.0.2.1")));

        List<CreateRewriteDto> pending = service(client).cleanupOutdatedAndExcluded(
                requests("example.com", "192.0.2.1"));

        assertTrue(pending.isEmpty());
        assertEquals(List.of("outdated"), client.deleted);
    }

    @Test
    void excludesExistingAndNewNames() {
        FakeClient client = new FakeClient(List.of(
                new RewriteDto("excluded", "blocked.test", "192.0.2.1")));
        List<CreateRewriteDto> pending = service(client, "blocked.test")
                .cleanupOutdatedAndExcluded(requests(
                        "blocked.test", "192.0.2.1",
                        "api.blocked.test", "192.0.2.1",
                        "kept.test", "192.0.2.1"));

        assertEquals(List.of("kept.test"), pending.stream().map(CreateRewriteDto::name).toList());
        assertEquals(List.of("excluded"), client.deleted);
    }

    @Test
    void keepsSourcePriorityAndOrder() {
        Map<String, CreateRewriteDto> result = service(new FakeClient(List.of())).buildNewRewrites(List.of(
                new BypassRoute("192.0.2.1", "z.test"),
                new BypassRoute("192.0.2.2", "a.test"),
                new BypassRoute("192.0.2.3", "z.test")));
        assertEquals(List.of("z.test", "a.test"), List.copyOf(result.keySet()));
        assertEquals("192.0.2.1", result.get("z.test").content());
    }

    private static Map<String, CreateRewriteDto> requests(String... pairs) {
        Map<String, CreateRewriteDto> result = new LinkedHashMap<>();
        for (int i = 0; i < pairs.length; i += 2) {
            result.put(pairs[i], new CreateRewriteDto(pairs[i], pairs[i + 1]));
        }
        return result;
    }

    private static List<RewriteDto> existing(int count) {
        return IntStream.range(0, count)
                .mapToObj(i -> new RewriteDto("id" + i, "old" + i + ".test", "192.0.2.1")).toList();
    }

    private static NextDnsRewriteService service(FakeClient client, String... excluded) {
        return new NextDnsRewriteService(client, new ExcludeRedirectCheckService(
                new ExcludeRedirectSettingsLoader() {
                    @Override
                    public List<String> loadIgnoredDomains() {
                        return List.of(excluded);
                    }
                }));
    }

    private static class FakeClient extends NextDnsRewriteClient {
        final List<RewriteDto> rows;
        final List<String> deleted = new ArrayList<>();

        FakeClient(List<RewriteDto> rows) {
            this.rows = new ArrayList<>(rows);
        }

        @Override
        public List<RewriteDto> fetchRewrites() {
            return List.copyOf(rows);
        }

        @Override
        public SingleRewriteResponse deleteRewriteById(String id) {
            deleted.add(id);
            rows.removeIf(r -> r.id().equals(id));
            return null;
        }

        @Override
        public SingleRewriteResponse saveRewrite(CreateRewriteDto request) {
            if (rows.size() >= 500) {
                throw new IllegalStateException("listLimitExceeded: rewrites, limit 500");
            }
            rows.add(new RewriteDto("new-" + request.name(), request.name(), request.content()));
            return new SingleRewriteResponse();
        }
    }
}
