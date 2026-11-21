package com.novibe.dns.next_dns.service;

import com.novibe.common.base_structures.BypassRoute;
import com.novibe.common.exception.UserInputException;
import com.novibe.common.service.ExcludeRedirectCheckService;
import com.novibe.common.util.Log;
import com.novibe.dns.next_dns.http.NextDnsRateLimitedApiProcessor;
import com.novibe.dns.next_dns.http.NextDnsRewriteClient;
import com.novibe.dns.next_dns.http.dto.request.CreateRewriteDto;
import com.novibe.dns.next_dns.http.dto.response.rewrite.RewriteDto;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

@Service
@RequiredArgsConstructor
public class NextDnsRewriteService {

    private static final int MAX_REWRITES = 500;

    private final NextDnsRewriteClient nextDnsRewriteClient;
    private final ExcludeRedirectCheckService excludeRedirectCheckService;

    public Map<String, CreateRewriteDto> buildNewRewrites(List<BypassRoute> overrides) {
        Map<String, CreateRewriteDto> rewriteDtos = new LinkedHashMap<>();
        overrides.forEach(route -> rewriteDtos.putIfAbsent(route.website(), new CreateRewriteDto(route.website(), route.ip())));
        return rewriteDtos;
    }

    public List<CreateRewriteDto> cleanupOutdatedAndExcluded(Map<String, CreateRewriteDto> newRewriteRequests) {
        List<RewriteDto> existingRewrites = getExistingRewrites();
        Map<String, CreateRewriteDto> desired = new LinkedHashMap<>(newRewriteRequests);
        desired.keySet().removeIf(excludeRedirectCheckService::shouldExclude);

        // Unknown existing rules remain authoritative between a parent and its descendants.
        Map<String, String> effective = new LinkedHashMap<>();
        for (RewriteDto existing : existingRewrites) {
            if (!excludeRedirectCheckService.shouldExclude(existing.name())) {
                effective.merge(existing.name(), existing.content(), (a, b) -> a.equals(b) ? a : "");
            }
        }
        desired.forEach((domain, request) -> effective.put(domain, request.content()));
        Map<String, CreateRewriteDto> compacted = new LinkedHashMap<>();
        desired.forEach((domain, request) -> {
            if (!request.content().equals(inheritedAnswer(domain, effective))) {
                compacted.put(domain, request);
            }
        });

        List<String> obsoleteIds = new ArrayList<>();
        Set<String> satisfied = new HashSet<>();
        for (RewriteDto existing : existingRewrites) {
            String domain = existing.name();
            CreateRewriteDto request = compacted.get(domain);
            if (excludeRedirectCheckService.shouldExclude(domain)
                    || desired.containsKey(domain) && request == null
                    || request != null && !request.content().equals(existing.content())) {
                obsoleteIds.add(existing.id());
            } else if (request != null) {
                satisfied.add(domain);
            }
        }
        List<CreateRewriteDto> pending = compacted.values().stream()
                .filter(request -> !satisfied.contains(request.name())).toList();
        int retained = existingRewrites.size() - obsoleteIds.size();
        int projected = retained + pending.size();
        Log.common("NextDNS rewrites: %s source domains, %s compacted rules, %s retained existing, %s additions, %s final."
                .formatted(desired.size(), compacted.size(), retained, pending.size(), projected));
        if (projected > MAX_REWRITES) {
            throw UserInputException.noStackTrace(
                    "NextDNS allows at most %s rewrites per profile; planned total is %s. No rewrites were changed. "
                            .formatted(MAX_REWRITES, projected)
                            + "Review obsolete existing rules or reduce REDIRECT sources; splitting requests into batches does not raise this limit.");
        }

        if (!obsoleteIds.isEmpty()) {
            Log.io("Removing %s outdated, excluded or redundant rewrites from NextDNS".formatted(obsoleteIds.size()));
            NextDnsRateLimitedApiProcessor.callApi(obsoleteIds, nextDnsRewriteClient::deleteRewriteById);
        }
        return pending;
    }

    private static String inheritedAnswer(String domain, Map<String, String> answers) {
        while (domain.contains(".")) {
            domain = domain.substring(domain.indexOf('.') + 1);
            if (answers.containsKey(domain)) {
                return answers.get(domain);
            }
        }
        return null;
    }

    public List<RewriteDto> getExistingRewrites() {
        Log.io("Fetching existing rewrites from NextDNS");
        return nextDnsRewriteClient.fetchRewrites();
    }

    public void saveRewrites(List<CreateRewriteDto> createRewriteDtos) {
        Log.io("Saving %s new rewrites to NextDNS...".formatted(createRewriteDtos.size()));
        NextDnsRateLimitedApiProcessor.callApi(createRewriteDtos, nextDnsRewriteClient::saveRewrite);
    }

    public void removeAll() {
        Log.io("Fetching existing rewrites from NextDNS");
        List<RewriteDto> list = nextDnsRewriteClient.fetchRewrites();
        List<String> ids = list.stream().map(RewriteDto::id).toList();
        Log.io("Removing rewrites from NextDNS");
        NextDnsRateLimitedApiProcessor.callApi(ids, nextDnsRewriteClient::deleteRewriteById);
    }
}
