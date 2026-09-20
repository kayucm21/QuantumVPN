package com.quantumvpn.hardening

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.put

enum class AdBlockLevel {
    Light,
    Standard,
    Hard,
    /** Hard lists + весь DNS сессии идёт через блокирующий upstream (AdGuard): ловит и новые/неизвестные ad-домены. */
    Maximum,
}

/** Категории контента поверх базовых списков рекламы/трекеров. */
enum class AdBlockCategory {
    /** 18+ / adult-сети. */
    Adult,
    /** Соцсети и мессенджеры. */
    Social,
    /** Азартные игры / ставки. */
    Gambling,
    /** Региональные (RU) рекламные и трекер-сети. */
    Regional,
}

data class AdBlockOptions(
    val enabled: Boolean = true,
    val level: AdBlockLevel = AdBlockLevel.Standard,
    val trackersOnly: Boolean = false,
    val whitelistSuffixes: List<String> = emptyList(),
    /** Весь DNS сайтов/приложений → DoH dns.adguard-dns.com через VPN-proxy. */
    val useOnlineFilterDns: Boolean = true,
    /** Дополнительные категории контента для блокировки (независимо от [level]). */
    val categories: Set<AdBlockCategory> = emptySet(),
)

/**
 * Runtime-only ad/tracker blocking for the whole VPN session:
 * - route `reject` (TCP/UDP/QUIC не проходят к ad-хостам);
 * - DNS reject (NXDOMAIN) для известных ad/tracker доменов;
 * - при `useOnlineFilterDns`: весь DNS сайтов и приложений → DoH
 *   https://dns.adguard-dns.com/dns-query через VPN-proxy.
 *
 * Работает системно: TUN принимает весь трафик устройства, поэтому блокировка
 * распространяется на все приложения, пока VPN активен.
 */
object AdBlockHardening {
    const val DNS_BLOCK_TAG = "dns-block-ads-qv"
    const val ONLINE_FILTER_DNS_TAG = "dns-adguard-filter-qv"
    const val ONLINE_FILTER_HOST = "dns.adguard-dns.com"
    const val ONLINE_FILTER_IPV4 = "94.140.14.14"
    const val ROUTE_RULE_TAG = "zapret-adblock-route"

    fun apply(root: JsonObject, enabled: Boolean): JsonObject =
        apply(root, AdBlockOptions(enabled = enabled))

    fun apply(
        root: JsonObject,
        options: AdBlockOptions,
        proxyTag: String? = null,
    ): JsonObject {
        if (!options.enabled) return strip(root)
        val suffixes = filteredSuffixes(options)
        val domains = filteredDomains(options)
        val keywords = if (options.trackersOnly) TRACKER_KEYWORDS else AD_KEYWORDS
        if (suffixes.isEmpty() && domains.isEmpty() && keywords.isEmpty()) return strip(root)

        val onlineDns = options.useOnlineFilterDns && !proxyTag.isNullOrBlank()
        // Весь DNS сессии → AdGuard DoH (сайты, приложения, in-app) при включённом онлайн-фильтре.
        val routeAllDns = onlineDns

        var next = ensureInfrastructure(root)
        next = applyRouteReject(next, suffixes, domains, keywords)
        next = applyDnsBlock(next, suffixes, domains, keywords, options, proxyTag, routeAllDns)
        return next
    }

    fun suffixesFor(options: AdBlockOptions): List<String> = filteredSuffixes(options)

    fun ruleCount(options: AdBlockOptions): Int {
        if (!options.enabled) return 0
        val suffixes = filteredSuffixes(options)
        val domains = filteredDomains(options)
        val keywords = if (options.trackersOnly) TRACKER_KEYWORDS else AD_KEYWORDS
        return suffixes.size + domains.size + keywords.size
    }

    fun strip(root: JsonObject): JsonObject {
        var next = stripRoute(root)
        next = stripDns(next)
        return next
    }

    private fun filteredSuffixes(options: AdBlockOptions): List<String> {
        val base = (when {
            options.trackersOnly -> TRACKER_SUFFIXES
            options.level == AdBlockLevel.Light -> LIGHT_SUFFIXES + YOUTUBE_AD_SUFFIXES
            options.level == AdBlockLevel.Hard -> HARD_SUFFIXES + YOUTUBE_AD_SUFFIXES
            options.level == AdBlockLevel.Maximum -> MAXIMUM_SUFFIXES + YOUTUBE_AD_SUFFIXES
            else -> STANDARD_SUFFIXES + YOUTUBE_AD_SUFFIXES
        } + categorySuffixes(options))
        return base.filterNot { suffix ->
            options.whitelistSuffixes.any { w ->
                suffix.equals(w, ignoreCase = true) ||
                    suffix.endsWith(".$w", ignoreCase = true) ||
                    w.endsWith(".$suffix", ignoreCase = true)
            }
        }.distinct()
    }

    private fun filteredDomains(options: AdBlockOptions): List<String> {
        if (options.trackersOnly) return emptyList()
        val base = (when (options.level) {
            AdBlockLevel.Light -> LIGHT_DOMAINS
            AdBlockLevel.Hard -> HARD_DOMAINS
            AdBlockLevel.Maximum -> MAXIMUM_DOMAINS
            AdBlockLevel.Standard -> STANDARD_DOMAINS
        } + categoryDomains(options))
        return base.filterNot { domain ->
            options.whitelistSuffixes.any { w ->
                domain.equals(w, ignoreCase = true) ||
                    domain.endsWith(".$w", ignoreCase = true)
            }
        }.distinct()
    }

    private fun ensureInfrastructure(root: JsonObject): JsonObject {
        var next = root
        if (next["dns"] !is JsonObject) {
            next = JsonObject(
                next.toMutableMap().apply {
                    this["dns"] = buildJsonObject {
                        put(
                            "servers",
                            JsonArray(
                                listOf(
                                    buildJsonObject {
                                        put("type", "local")
                                        put("tag", "local-dns")
                                    },
                                ),
                            ),
                        )
                        put("final", "local-dns")
                        put("rules", JsonArray(emptyList()))
                    }
                },
            )
        }
        if (next["route"] !is JsonObject) {
            next = JsonObject(
                next.toMutableMap().apply {
                    this["route"] = buildJsonObject {
                        put("rules", JsonArray(emptyList()))
                        put("final", "direct")
                    }
                },
            )
        }
        return ensureDnsHijack(next)
    }

    /** Без hijack-dns запросы уходят в системный DNS и ad-block не срабатывает. */
    private fun ensureDnsHijack(root: JsonObject): JsonObject {
        val route = root["route"] as? JsonObject ?: return root
        val rules = (route["rules"] as? JsonArray)?.toMutableList() ?: mutableListOf()

        fun hasHijack(port: String? = null, protocol: String? = null): Boolean =
            rules.any { element ->
                val rule = element as? JsonObject ?: return@any false
                if (rule.string("action") != "hijack-dns") return@any false
                when {
                    port != null ->
                        (rule["port"] as? JsonPrimitive)?.contentOrNull == port
                    protocol != null ->
                        (rule["protocol"] as? JsonPrimitive)?.contentOrNull == protocol
                    else -> true
                }
            }

        if (!hasHijack(port = "53")) {
            rules.add(
                0,
                buildJsonObject {
                    put("port", 53)
                    put("action", "hijack-dns")
                },
            )
        }
        // DoH/DoT в приложениях (Chrome, Android Private DNS off-path) — перехват по protocol.
        if (!hasHijack(protocol = "dns")) {
            rules.add(
                0,
                buildJsonObject {
                    put("protocol", "dns")
                    put("action", "hijack-dns")
                },
            )
        }

        val dns = root["dns"] as? JsonObject
        val routeMut = route.toMutableMap()
        routeMut["rules"] = JsonArray(rules)
        if (dns != null && routeMut["default_domain_resolver"] == null) {
            val finalTag = dns.string("final") ?: "local-dns"
            routeMut["default_domain_resolver"] = JsonPrimitive(finalTag)
        }
        return JsonObject(
            root.toMutableMap().apply {
                this["route"] = JsonObject(routeMut)
            },
        )
    }

    private fun applyRouteReject(
        root: JsonObject,
        suffixes: List<String>,
        domains: List<String>,
        keywords: List<String>,
    ): JsonObject {
        val route = root["route"] as? JsonObject ?: return root
        val rules = (route["rules"] as? JsonArray)?.toMutableList() ?: mutableListOf()
        rules.removeAll(::isManagedAdRouteRule)

        if (suffixes.isNotEmpty()) {
            rules.add(
                0,
                buildJsonObject {
                    put("action", "reject")
                    put("domain_suffix", JsonArray(suffixes.map(::JsonPrimitive)))
                },
            )
        }
        if (domains.isNotEmpty()) {
            rules.add(
                0,
                buildJsonObject {
                    put("action", "reject")
                    put("domain", JsonArray(domains.map(::JsonPrimitive)))
                },
            )
        }
        if (keywords.isNotEmpty()) {
            rules.add(
                0,
                buildJsonObject {
                    put("action", "reject")
                    put("domain_keyword", JsonArray(keywords.map(::JsonPrimitive)))
                },
            )
        }

        return JsonObject(
            root.toMutableMap().apply {
                this["route"] = JsonObject(
                    route.toMutableMap().apply {
                        this["rules"] = JsonArray(rules)
                    },
                )
            },
        )
    }

    private fun applyDnsBlock(
        root: JsonObject,
        suffixes: List<String>,
        domains: List<String>,
        keywords: List<String>,
        options: AdBlockOptions,
        proxyTag: String?,
        routeAllDns: Boolean,
    ): JsonObject {
        val dns = root["dns"] as? JsonObject ?: return root
        val rules = (dns["rules"] as? JsonArray)?.toMutableList() ?: mutableListOf()
        rules.removeAll(::isManagedAdDnsRule)

        val servers = (dns["servers"] as? JsonArray)?.toMutableList() ?: mutableListOf()
        val onlineDns = options.useOnlineFilterDns && !proxyTag.isNullOrBlank()
        if (onlineDns) {
            ensureOnlineFilterServer(servers, checkNotNull(proxyTag))
        }

        if (suffixes.isNotEmpty()) {
            rules.add(0, dnsRejectRule(suffixes = suffixes))
        }
        if (domains.isNotEmpty()) {
            rules.add(0, dnsRejectRule(domains = domains))
        }
        if (keywords.isNotEmpty()) {
            if (onlineDns) {
                rules.add(0, dnsRouteRule(keywords = keywords, server = ONLINE_FILTER_DNS_TAG))
            } else {
                rules.add(0, dnsRejectRule(keywords = keywords))
            }
        }
        if (routeAllDns) {
            // Весь остальной DNS (сайты + приложения) → dns.adguard-dns.com.
            rules.add(
                buildJsonObject {
                    put("action", "route")
                    put("server", ONLINE_FILTER_DNS_TAG)
                },
            )
        }

        // История просмотров YouTube идёт через s.youtube.com — не топить AdGuard/reject.
        rules.add(
            0,
            dnsRouteRule(
                domains = YOUTUBE_HISTORY_ALLOW_DOMAINS,
                server = if (routeAllDns) {
                    ONLINE_FILTER_DNS_TAG
                } else {
                    dns.string("final") ?: "local-dns"
                },
            ),
        )

        val dnsMut = dns.toMutableMap()
        dnsMut["rules"] = JsonArray(rules)
        dnsMut["servers"] = JsonArray(servers)
        if (routeAllDns) {
            // Финальный резолвер сессии — AdGuard (блокирует рекламу на неизвестных доменах).
            dnsMut["final"] = JsonPrimitive(ONLINE_FILTER_DNS_TAG)
        }

        return JsonObject(
            root.toMutableMap().apply {
                this["dns"] = JsonObject(dnsMut)
            },
        )
    }

    private fun dnsRejectRule(
        suffixes: List<String> = emptyList(),
        domains: List<String> = emptyList(),
        keywords: List<String> = emptyList(),
    ): JsonObject = buildJsonObject {
        if (suffixes.isNotEmpty()) put("domain_suffix", JsonArray(suffixes.map(::JsonPrimitive)))
        if (domains.isNotEmpty()) put("domain", JsonArray(domains.map(::JsonPrimitive)))
        if (keywords.isNotEmpty()) put("domain_keyword", JsonArray(keywords.map(::JsonPrimitive)))
        put("action", "reject")
        put("method", "default")
    }

    private fun dnsRouteRule(
        suffixes: List<String> = emptyList(),
        domains: List<String> = emptyList(),
        keywords: List<String> = emptyList(),
        server: String,
    ): JsonObject = buildJsonObject {
        if (suffixes.isNotEmpty()) put("domain_suffix", JsonArray(suffixes.map(::JsonPrimitive)))
        if (domains.isNotEmpty()) put("domain", JsonArray(domains.map(::JsonPrimitive)))
        if (keywords.isNotEmpty()) put("domain_keyword", JsonArray(keywords.map(::JsonPrimitive)))
        put("server", server)
    }

    private fun ensureOnlineFilterServer(servers: MutableList<JsonElement>, proxyTag: String) {
        servers.removeAll { element ->
            val tag = (element as? JsonObject)?.string("tag").orEmpty()
            tag == ONLINE_FILTER_DNS_TAG ||
                tag == "${ONLINE_FILTER_DNS_TAG}-host" ||
                tag == "${ONLINE_FILTER_DNS_TAG}-ip"
        }
        val hostTag = "${ONLINE_FILTER_DNS_TAG}-host"
        val ipTag = "${ONLINE_FILTER_DNS_TAG}-ip"
        // DoH AdGuard: https://dns.adguard-dns.com/dns-query — реклама на сайтах и в приложениях.
        servers.add(
            buildJsonObject {
                put("type", "https")
                put("tag", hostTag)
                put("server", ONLINE_FILTER_HOST)
                put("server_port", 443)
                put("path", "/dns-query")
                put(
                    "tls",
                    buildJsonObject {
                        put("enabled", true)
                        put("server_name", ONLINE_FILTER_HOST)
                    },
                )
                put("detour", proxyTag)
            },
        )
        servers.add(
            buildJsonObject {
                put("type", "https")
                put("tag", ipTag)
                put("server", ONLINE_FILTER_IPV4)
                put("server_port", 443)
                put("path", "/dns-query")
                put(
                    "tls",
                    buildJsonObject {
                        put("enabled", true)
                        put("server_name", ONLINE_FILTER_HOST)
                    },
                )
                put("detour", proxyTag)
            },
        )
        servers.add(
            buildJsonObject {
                put("type", "fallback")
                put("tag", ONLINE_FILTER_DNS_TAG)
                put(
                    "servers",
                    JsonArray(listOf(JsonPrimitive(hostTag), JsonPrimitive(ipTag))),
                )
                put("strategy", "parallel")
            },
        )
    }

    private fun stripRoute(root: JsonObject): JsonObject {
        val route = root["route"] as? JsonObject ?: return root
        val rules = (route["rules"] as? JsonArray)?.toMutableList() ?: return root
        val before = rules.size
        rules.removeAll(::isManagedAdRouteRule)
        if (rules.size == before) return root
        return JsonObject(
            root.toMutableMap().apply {
                this["route"] = JsonObject(
                    route.toMutableMap().apply {
                        this["rules"] = JsonArray(rules)
                    },
                )
            },
        )
    }

    private fun stripDns(root: JsonObject): JsonObject {
        val dns = root["dns"] as? JsonObject ?: return root
        val rules = (dns["rules"] as? JsonArray)?.toMutableList() ?: return root
        val servers = (dns["servers"] as? JsonArray)?.toMutableList() ?: return root
        val rulesBefore = rules.size
        rules.removeAll(::isManagedAdDnsRule)
        val serversBefore = servers.size
        servers.removeAll { element ->
            val tag = (element as? JsonObject)?.string("tag").orEmpty()
            tag == DNS_BLOCK_TAG ||
                tag == "${DNS_BLOCK_TAG}-sink" ||
                tag == ONLINE_FILTER_DNS_TAG ||
                tag == "${ONLINE_FILTER_DNS_TAG}-host" ||
                tag == "${ONLINE_FILTER_DNS_TAG}-ip"
        }
        if (rules.size == rulesBefore && servers.size == serversBefore) return root
        return JsonObject(
            root.toMutableMap().apply {
                this["dns"] = JsonObject(
                    dns.toMutableMap().apply {
                        this["rules"] = JsonArray(rules)
                        this["servers"] = JsonArray(servers)
                    },
                )
            },
        )
    }

    private fun isManagedAdRouteRule(element: JsonElement): Boolean {
        val rule = element as? JsonObject ?: return false
        if (rule.string("action") != "reject") return false
        val suffixes = (rule["domain_suffix"] as? JsonArray)
            ?.mapNotNull { (it as? JsonPrimitive)?.contentOrNull }
            .orEmpty()
        if (suffixes.any { it in KNOWN_AD_SUFFIXES }) return true
        val domains = (rule["domain"] as? JsonArray)
            ?.mapNotNull { (it as? JsonPrimitive)?.contentOrNull }
            .orEmpty()
        if (domains.any { it in KNOWN_AD_DOMAINS }) return true
        return rule["domain_keyword"] != null && isKnownAdKeywordRule(rule)
    }

    private fun isKnownAdKeywordRule(rule: JsonObject): Boolean {
        val keywords = (rule["domain_keyword"] as? JsonArray)
            ?.mapNotNull { (it as? JsonPrimitive)?.contentOrNull }
            .orEmpty()
        return keywords.any { it in KNOWN_AD_KEYWORDS }
    }

    private fun isManagedAdDnsRule(element: JsonElement): Boolean {
        val rule = element as? JsonObject ?: return false
        val server = rule.string("server") ?: return false
        return server == DNS_BLOCK_TAG ||
            server == ONLINE_FILTER_DNS_TAG ||
            server == "${ONLINE_FILTER_DNS_TAG}-host" ||
            server == "${ONLINE_FILTER_DNS_TAG}-ip"
    }

    private fun JsonObject.string(name: String): String? =
        (get(name) as? JsonPrimitive)?.contentOrNull

    // ----- Ключевые слова -----
    private val AD_KEYWORDS = listOf(
        "adservice", "adsystem", "adserver", "adtrack", "adnxs", "doubleclick",
        "googlesyndication", "advertising", "pagead", "popup", "banner", "promo",
        "sponsor", "adview", "adsmedia", "adnetwork", "adbanner", "adclient",
        "adexchange", "adengine", "adfallback", "adimg", "adtile", "adver",
        "affiliate", "banniere", "clicktag", "mediamath", "pubads", "richmedia",
        "rtb", "taboola", "teads", "tremor", "tracker", "telemetry", "metrics",
        "pixel", "beacon", "heatmap", "sessioncam", "clicktale",
    )

    private val TRACKER_KEYWORDS = listOf(
        "analytics", "tracking", "tracker", "telemetry", "metrics", "stat.",
        "pixel", "beacon", "heatmap", "tagmanager", "datacollect",
        "events-collector", "ingest", "log-collector", "telemetry-ingest",
    )

    // ----- Категории контента -----
    private val CATEGORY_SUFFIXES: Map<AdBlockCategory, List<String>> = mapOf(
        AdBlockCategory.Adult to listOf(
            "pornhub.com", "xvideos.com", "xhamster.com", "youporn.com",
            "redtube.com", "xnxx.com", "porn.com", "adultfriendfinder.com",
            "onlyfans.com", "chaturbate.com", "livejasmin.com", "cam4.com",
            "porntube.com", "youjizz.com", "tube8.com", "keezmovies.com",
            "drtuber.com", "nuvid.com", "pornhd.com", "hellporno.com",
            "hqporner.com", "eporner.com", "xhamster.xxx",
        ),
        AdBlockCategory.Social to listOf(
            "facebook.com", "instagram.com", "twitter.com", "x.com",
            "tiktok.com", "vk.com", "ok.ru", "pinterest.com", "reddit.com",
            "snapchat.com", "linkedin.com", "tumblr.com", "discord.com",
            "telegram.org", "whatsapp.com", "youtube.com", "twitch.tv",
            "threads.net", "quora.com", "weibo.com", "vimeo.com", "medium.com",
        ),
        AdBlockCategory.Gambling to listOf(
            "bet365.com", "betfair.com", "pokerstars.com", "888.com",
            "williamhill.com", "unibet.com", "casino.com", "ladbrokes.com",
            "bwin.com", "1xbet.com", "parimatch.com", "fonbet.ru", "winline.ru",
            "leon.ru", "marathonbet.ru", "ligastavok.ru", "xbet.com",
            "megapari.com", "betcity.ru", "olimp.bet",
        ),
        AdBlockCategory.Regional to listOf(
            "smi2.ru", "marketgid.com", "lentainform.com", "relap.io",
            "adme.ru", "fishki.net", "pikabu.ru", "adlabs.ru", "rbc.ru",
            "kommersant.ru", "vedomosti.ru", "lenta.ru", "gazeta.ru", "kp.ru",
            "aif.ru",
        ),
    )

    private val CATEGORY_DOMAINS: Map<AdBlockCategory, List<String>> = mapOf(
        AdBlockCategory.Adult to listOf(
            "www.pornhub.com", "www.xvideos.com", "www.xhamster.com",
            "www.redtube.com", "www.xnxx.com", "www.porn.com", "www.youporn.com",
            "onlyfans.com", "chaturbate.com",
        ),
        AdBlockCategory.Social to listOf(
            "www.facebook.com", "www.instagram.com", "www.tiktok.com",
            "www.vk.com", "www.ok.ru", "www.reddit.com", "discord.com",
            "telegram.org", "www.youtube.com", "www.twitch.tv",
        ),
        AdBlockCategory.Gambling to listOf(
            "www.bet365.com", "www.pokerstars.com", "www.1xbet.com",
            "www.fonbet.ru", "www.parimatch.com", "www.winline.ru",
            "www.ligastavok.ru", "www.marathonbet.ru",
        ),
        AdBlockCategory.Regional to listOf(
            "www.smi2.ru", "www.marketgid.com", "www.relap.io",
            "www.pikabu.ru", "www.lenta.ru", "www.gazeta.ru", "www.kp.ru",
        ),
    )

    private fun categorySuffixes(options: AdBlockOptions): List<String> =
        options.categories.flatMap { CATEGORY_SUFFIXES[it].orEmpty() }

    private fun categoryDomains(options: AdBlockOptions): List<String> =
        options.categories.flatMap { CATEGORY_DOMAINS[it].orEmpty() }

    // ----- Лёгкий уровень -----
    private val LIGHT_SUFFIXES = listOf(
        "doubleclick.net", "googlesyndication.com", "googleadservices.com",
        "pagead2.googlesyndication.com", "adsrvr.org", "adnxs.com",
    )

    private val TRACKER_SUFFIXES = listOf(
        "google-analytics.com", "googletagmanager.com", "scorecardresearch.com",
        "hotjar.com", "clarity.ms", "facebook.net", "quantserve.com",
        "segment.io", "mixpanel.com", "amplitude.com", "appsflyer.com",
        "adjust.com", "branch.io", "crashlytics.com", "flurry.com",
        "newrelic.com", "fullstory.com", "inspectlet.com", "mouseflow.com",
        "luckyorange.com", "crazyegg.com", "optimizely.com", "kissmetrics.com",
        "parsely.com", "chartbeat.com", "nielsen.com", "comscore.com",
        "bluekai.com", "liveramp.com", "lotame.com", "neustar.biz", "tapad.com",
    )

    // ----- Стандартный уровень (глобальные + RU ad/tracker сети) -----
    private val STANDARD_SUFFIXES = LIGHT_SUFFIXES + TRACKER_SUFFIXES + listOf(
        "adservice.google.com", "moatads.com", "taboola.com", "outbrain.com",
        "criteo.com", "pubmatic.com", "openx.net", "rubiconproject.com",
        "yandexadexchange.net", "an.yandex.ru", "ads.vk.com", "ad.mail.ru",
        "adfox.ru", "applovin.com", "unity3d.com", "ironsrc.mobi",
        "chartboost.com", "mopub.com", "inmobi.com", "vungle.com", "adcolony.com",
        "tapjoy.com", "supersonicads.com", "startappservice.com", "advertising.com",
        "adform.net", "adsafeprotected.com", "ads-twitter.com", "ads.linkedin.com",
        "casalemedia.com", "exelator.com", "yieldmo.com", "smartadserver.com",
        "amazon-adsystem.com", "media.net", "adriver.ru", "begun.ru", "relap.io",
        "betweendigital.com", "getadmiral.com", "propellerads.com", "popads.net",
        "popcash.net", "exoclick.com", "trafficfactory.biz", "hilltopads.net",
        "adsterra.com", "mgid.com", "revcontent.com", "zergnet.com", "33across.com",
        "adblade.com", "adbutler.com", "adcash.com", "adgear.com", "adition.com",
        "adkernel.com", "admarket.com", "admeld.com", "adnium.com", "adocean.com",
        "adpepper.com", "adperfect.com", "adplus.com", "adreactor.com", "adroll.com",
        "adscale.com", "adtech.de", "adtelligent.com", "adthrive.com", "adverline.com",
        "adverticum.com", "adview.com", "adzerk.net", "agkn.com", "amobee.com",
        "aniview.com", "appnexus.com", "atomx.com", "audienceproject.com",
        "axonix.com", "bidr.io", "bidtellect.com", "bidvertiser.com", "buzzcity.com",
        "buzzoola.com", "c1exchange.com", "centro.net", "celtra.com", "chango.com",
        "collect.media", "conversantmedia.com", "cpxinteractive.com", "cxense.com",
        "dataxu.com", "deepintent.com", "demandbase.com", "dianomi.com", "dotomi.com",
        "dstillery.com", "e-planning.net", "etargetnet.com", "everesttech.net",
        "falkag.net", "flashtalking.com", "gumgum.com", "huntmads.com", "improve-digital.com",
        "indexexchange.com", "innity.com", "intentiq.com", "iponweb.net", "jetlore.com",
        "jivox.com", "kochava.com", "kraken.me", "ligatus.com", "linqia.com",
        "liveintent.com", "madisonlogic.com", "marchex.com", "metaclick.com",
        "monetate.com", "mookie1.com", "nativo.com", "netseer.com", "nugg.ad",
        "optimatic.com", "padstm.com", "peer39.com", "pixfuture.com", "platform161.com",
        "positiveads.com", "proximic.com", "pulsepoint.com", "quantcast.com",
        "radiumone.com", "rakuten.com", "resonance.com", "revsci.net", "satori.co",
        "sekindo.com", "servingsys.com", "sizmek.com", "simpli.fi", "sociomantic.com",
        "sojern.com", "sonobi.com", "specificmedia.com", "spotx.tv", "strossle.com",
        "swoop.com", "teads.tv", "thetradedesk.com", "triplelift.com", "trustx.org",
        "turn.com", "undertone.com", "unruly.co", "verizonmedia.com", "videology.com",
        "visualdna.com", "widespace.com", "xaxis.com", "yahoo.com", "yieldex.com",
        "zedo.com", "zemanta.com", "hyad.net", "smi2.ru", "marketgid.com",
        "lentainform.com", "getadmiral.com", "ezodn.com", "betweendigital.com",
        "relap.io", "begemot.media",
    )

    private val HARD_SUFFIXES = STANDARD_SUFFIXES + listOf(
        "adspirit.de", "adscendmedia.com", "adshost.net", "adswizz.com", "advomatic.com",
        "beamimpact.com", "brilig.com", "bttrack.com", "clickbooth.com", "clicksor.com",
        "cognitiv.com", "crimtan.com", "criteo-sync.com", "curalate.com", "datacratic.com",
        "delivr.com", "dotandads.com", "dsnextgen.com", "engagebdr.com", "fyx.com",
        "gamned.com", "globaltakeoff.net", "i-mobile.co.jp", "imrworldwide.com", "interpolls.com",
        "jumptap.com", "kargo.com", "kiosked.com", "krux.com", "lijit.com", "loopme.com",
        "mdotm.com", "mediaglu.com", "mediamath.com", "microad.jp", "mochimedia.com",
        "mobfox.com", "mobvista.com", "netmng.com", "npttech.com", "nudd.io", "ochre.com",
        "onestop.com", "optan.com", "parrable.com", "pointroll.com", "pubnative.net",
        "qriously.com", "readwhere.com", "resonate.com", "ringieraxelspringer.com",
        "roq.ad", "shopzilla.com", "simplifymedia.net", "smartclip.net", "smilewanted.com",
        "smaato.com", "sovrn.com", "storied.co", "stroer.com", "technorati.com",
        "telaria.com", "tremorvideo.com", "tribalfusion.com", "trafficjunky.net",
        "trafficmarket.com", "trueffect.com", "twiago.com", "unanimis.co.uk", "us.bidswitch.net",
        "valueclickmedia.com", "verticalacuity.com", "videoamps.com", "vidible.com",
        "viralad.com", "visible.measures.com", "vizen.com", "vmg1.com", "wikia.com",
        "xad.com", "yieldlab.de", "yume.com", "zantracker.com", "ziffdavis.com",
        "zinio.com", "zucks.co.jp", "aditude.net", "adman.gr", "adtaily.com",
        "bannersnack.com", "cubics.com", "deepintent.com", "dstillery.com", "eyereturn.com",
        "gwallet.com", "innity.com", "jivox.com", "nativo.com", "saymedia.com",
        "videology.com", "widespace.com", "xaxis.com", "yerdy.com", "yieldex.com",
    )

    private val MAXIMUM_SUFFIXES = HARD_SUFFIXES

    /** Hosts needed for watch history / InnerTube — never sinkhole these. */
    private val YOUTUBE_HISTORY_ALLOW_DOMAINS = listOf(
        "s.youtube.com",
        "youtubei.googleapis.com",
        "youtube.googleapis.com",
        "jnn-pa.googleapis.com",
    )

    /** Dedicated YouTube ad hosts (not googlevideo CDN, not s.youtube.com — history). */
    private val YOUTUBE_AD_DOMAINS = listOf(
        "ads.youtube.com",
        "ad.youtube.com",
        "ads.youtube-nocookie.com",
        "pagead2.googlesyndication.com",
        "pagead.googlesyndication.com",
        "ade.googlesyndication.com",
        "video-ad-overlay.googlesyndication.com",
        "googleads.g.doubleclick.net",
        "googleads2.g.doubleclick.net",
        "googleads3.g.doubleclick.net",
        "googleads4.g.doubleclick.net",
        "securepubads.g.doubleclick.net",
        "pubads.g.doubleclick.net",
        "pagead46.l.doubleclick.net",
        "ad.doubleclick.net",
        "static.doubleclick.net",
        "stats.g.doubleclick.net",
        "cm.g.doubleclick.net",
        "fls.doubleclick.net",
        "adx.g.doubleclick.net",
        "bid.g.doubleclick.net",
        "g.doubleclick.net",
        "partnerad.l.google.com",
        "googleadservices.com",
        "www.googleadservices.com",
        "partner.googleadservices.com",
        "pagead2.googleadservices.com",
        "adservice.google.com",
        "adservice.google.ru",
        "ads.google.com",
        "tpc.googlesyndication.com",
        "2mdn.net",
        "www.2mdn.net",
        "s0.2mdn.net",
        "s1.2mdn.net",
        "dt.adsafeprotected.com",
        "pixel.adsafeprotected.com",
        "static.adsafeprotected.com",
        "fwmrm.net",
        "7eer.net",
        "innovid.com",
        "serving-sys.com",
        "moatads.com",
        "doubleclick.net",
        "spotx.tv",
        "spotxchange.com",
        "tremorhub.com",
        "teads.tv",
        "ads.stickyadstv.com",
        "stickyadstv.com",
        "amazon-adsystem.com",
        "aax.amazon-adsystem.com",
        "c.amazon-adsystem.com",
        "flashtalking.com",
        "scorecardresearch.com",
        "imrworldwide.com",
        "www.googletagservices.com",
        "googletagservices.com",
    )

    private val YOUTUBE_AD_SUFFIXES = listOf(
        "googlesyndication.com",
        "doubleclick.net",
        "2mdn.net",
        "googleadservices.com",
        "moatads.com",
        "innovid.com",
        "fwmrm.net",
        "serving-sys.com",
        "adsafeprotected.com",
        "spotx.tv",
        "spotxchange.com",
        "tremorhub.com",
        "teads.tv",
        "stickyadstv.com",
        "amazon-adsystem.com",
        "googletagservices.com",
        "scorecardresearch.com",
        "imrworldwide.com",
    )

    // ----- Точные домены -----
    private val LIGHT_DOMAINS = listOf(
        "pagead2.googlesyndication.com", "static.doubleclick.net",
        "ads.youtube.com", "ad.youtube.com",
    ) + YOUTUBE_AD_DOMAINS

    private val STANDARD_DOMAINS = (LIGHT_DOMAINS + listOf(
        "www.googleadservices.com", "ads-api.twitter.com",
        "ads.facebook.com", "googleads.g.doubleclick.net", "securepubads.g.doubleclick.net",
        "tpc.googlesyndication.com", "ad.doubleclick.net", "pagead.googlesyndication.com",
        "adservice.google.com", "googleadservices.com", "partner.googleadservices.com",
        "ade.googlesyndication.com", "pagead46.l.doubleclick.net", "googleads4.g.doubleclick.net",
        "googleads2.g.doubleclick.net", "googleads3.g.doubleclick.net",
        "adeventtracker.spotify.com", "ads.tiktok.com", "business.tiktok.com",
        "ads.snapchat.com", "ads.pinterest.com", "ads.reddit.com", "ads.twitch.tv",
        "ads.discord.com", "ads.linkedin.com", "ads.quora.com", "ads.microsoft.com",
        "ads.apple.com", "ads.amazon.com", "ads.netflix.com", "ads.bing.com",
        "ads.yahoo.com", "ads.baidu.com", "ads.alibaba.com", "ads.taobao.com",
        "ads.jd.com", "ads.ozon.ru", "ads.wildberries.ru", "ads.avito.ru",
        "ads.beeline.ru", "ads.mts.ru", "ads.megafon.ru", "ads.rt.ru", "ads.tele2.ru",
        "ads.sberbank.ru", "ads.tinkoff.ru", "ads.alfabank.ru", "ads.vtb.ru",
        "ads.magnit.ru", "ads.x5.ru", "ads.dns-shop.ru", "ads.dns.ru", "ads.rbc.ru",
        "ads.kommersant.ru", "ads.vedomosti.ru", "ads.lenta.ru", "ads.gazeta.ru",
        "ads.kp.ru", "ads.aif.ru",
    )).distinct()

    private val HARD_DOMAINS = STANDARD_DOMAINS + listOf(
        "googleads.g.doubleclick.net", "ad.doubleclick.net",
        "pagead.googlesyndication.com", "static.doubleclick.net",
        "googleadservices.com", "partner.googleadservices.com", "adsystem.com",
        "s2s-mobile.adnxs.com", "ib.adnxs.com", "ads-twitter.com", "ads-facebook.com",
        "ads-snapchat.com", "ads-pinterest.com", "ads-reddit.com", "ads-twitch.tv",
        "ads-discord.com", "ads-linkedin.com", "ads-quora.com", "ads-microsoft.com",
        "ads-apple.com", "ads-amazon.com", "ads-netflix.com", "ads-bing.com",
        "ads-yahoo.com", "ads-baidu.com", "ads-alibaba.com", "ads-taobao.com",
        "ads-jd.com", "ads-ozon.ru", "ads-wildberries.ru", "ads-avito.ru",
        "ads-beeline.ru", "ads-mts.ru", "ads-megafon.ru", "ads-rt.ru", "ads-tele2.ru",
        "ads-sberbank.ru", "ads-tinkoff.ru", "ads-alfabank.ru", "ads-vtb.ru",
        "ads-magnit.ru", "ads-x5.ru", "ads-dns-shop.ru", "ads-dns.ru", "ads-rbc.ru",
        "ads-kommersant.ru", "ads-vedomosti.ru", "ads-lenta.ru", "ads-gazeta.ru",
        "ads-kp.ru", "ads-aif.ru", "ads.yandex.ru", "ads.mail.ru", "ads.rambler.ru",
    )

    private val MAXIMUM_DOMAINS = HARD_DOMAINS

    private val KNOWN_AD_SUFFIXES: Set<String> =
        (LIGHT_SUFFIXES + TRACKER_SUFFIXES + STANDARD_SUFFIXES + HARD_SUFFIXES +
            CATEGORY_SUFFIXES.values.flatten())
            .map { it.lowercase() }.toSet()

    private val KNOWN_AD_DOMAINS: Set<String> =
        (LIGHT_DOMAINS + STANDARD_DOMAINS + HARD_DOMAINS +
            CATEGORY_DOMAINS.values.flatten())
            .map { it.lowercase() }.toSet()

    private val KNOWN_AD_KEYWORDS: Set<String> =
        (AD_KEYWORDS + TRACKER_KEYWORDS).map { it.lowercase() }.toSet()

    val AD_SUFFIXES: List<String> = STANDARD_SUFFIXES
}
