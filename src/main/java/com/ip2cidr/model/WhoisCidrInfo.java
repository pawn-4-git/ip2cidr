package com.ip2cidr.model;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;

/**
 * whois検索結果から抽出・整理されたCIDR単位の情報クラス。
 * 同一のCIDR領域に含まれる複数の入力IPアドレスは、この1つのインスタンスにまとめられます。
 */
public class WhoisCidrInfo {

    private final Cidr cidr;
    private final List<Cidr> allCidrs;
    private final String ipRange;
    private final Set<String> matchedIpAddresses;
    private final String country;
    private final String registrant;
    private final String netName;
    private final List<String> descriptions;
    private final List<String> adminContacts;
    private final List<String> techContacts;
    private final List<String> abuseContacts;
    private final String rawWhoisOutput;

    public WhoisCidrInfo(
            Cidr cidr,
            List<Cidr> allCidrs,
            String ipRange,
            List<String> matchedIpAddresses,
            String country,
            String registrant,
            String netName,
            List<String> descriptions,
            List<String> adminContacts,
            List<String> techContacts,
            List<String> abuseContacts,
            String rawWhoisOutput) {
        this.cidr = Objects.requireNonNull(cidr, "cidr must not be null");
        this.allCidrs = allCidrs == null || allCidrs.isEmpty()
                ? List.of(cidr)
                : Collections.unmodifiableList(new ArrayList<>(new LinkedHashSet<>(allCidrs)));
        this.ipRange = ipRange != null ? ipRange : "";
        this.matchedIpAddresses = new LinkedHashSet<>();
        if (matchedIpAddresses != null) {
            this.matchedIpAddresses.addAll(matchedIpAddresses);
        }
        this.country = country != null ? country : "";
        this.registrant = registrant != null ? registrant : "";
        this.netName = netName != null ? netName : "";
        this.descriptions = descriptions == null
                ? List.of()
                : Collections.unmodifiableList(new ArrayList<>(new LinkedHashSet<>(descriptions)));
        this.adminContacts = adminContacts == null
                ? List.of()
                : Collections.unmodifiableList(new ArrayList<>(new LinkedHashSet<>(adminContacts)));
        this.techContacts = techContacts == null
                ? List.of()
                : Collections.unmodifiableList(new ArrayList<>(new LinkedHashSet<>(techContacts)));
        this.abuseContacts = abuseContacts == null
                ? List.of()
                : Collections.unmodifiableList(new ArrayList<>(new LinkedHashSet<>(abuseContacts)));
        this.rawWhoisOutput = rawWhoisOutput != null ? rawWhoisOutput : "";
    }

    /**
     * このCIDR領域に該当する入力IPアドレスを追加します。
     *
     * @param ipAddress 追加するIPアドレス
     */
    public void addMatchedIpAddress(String ipAddress) {
        if (ipAddress != null && !ipAddress.isBlank()) {
            this.matchedIpAddresses.add(ipAddress.trim());
        }
    }

    /**
     * 代表となるCIDR情報（IPアドレスとプレフィックス長）を返します。
     */
    public Cidr getCidr() {
        return cidr;
    }

    /**
     * 検出されたすべてのCIDR一覧（inetnum範囲が複数CIDRに分割された場合などを含む）を返します。
     */
    public List<Cidr> getAllCidrs() {
        return allCidrs;
    }

    /**
     * IPアドレス範囲表記（例: "192.0.2.0 - 192.0.2.255"）を返します。
     */
    public String getIpRange() {
        return ipRange;
    }

    /**
     * このCIDRに分類された入力IPアドレスの一覧（追加順・重複なし）を返します。
     */
    public List<String> getMatchedIpAddresses() {
        return List.copyOf(matchedIpAddresses);
    }

    /**
     * 国コード（例: "JP", "US"）を返します。
     */
    public String getCountry() {
        return country;
    }

    /**
     * 登録組織名・登録者名（org-name / Organization / descr 等）を返します。
     */
    public String getRegistrant() {
        return registrant;
    }

    /**
     * ネットワーク名（netname / NetName）を返します。
     */
    public String getNetName() {
        return netName;
    }

    /**
     * 説明・備考情報（descr / Comment 等）の一覧を返します。
     */
    public List<String> getDescriptions() {
        return descriptions;
    }

    /**
     * 管理者連絡先（admin-c / OrgAdminHandle 等）の一覧を返します。
     */
    public List<String> getAdminContacts() {
        return adminContacts;
    }

    /**
     * 技術連絡先（tech-c / OrgTechHandle 等）の一覧を返します。
     */
    public List<String> getTechContacts() {
        return techContacts;
    }

    /**
     * アビューズ連絡先（abuse-mailbox / OrgAbuseEmail / abuse-c 等）の一覧を返します。
     */
    public List<String> getAbuseContacts() {
        return abuseContacts;
    }

    /**
     * 生のwhois出力テキスト全文を返します。
     */
    public String getRawWhoisOutput() {
        return rawWhoisOutput;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof WhoisCidrInfo that)) return false;
        return Objects.equals(cidr, that.cidr)
                && Objects.equals(allCidrs, that.allCidrs)
                && Objects.equals(ipRange, that.ipRange)
                && Objects.equals(matchedIpAddresses, that.matchedIpAddresses)
                && Objects.equals(country, that.country)
                && Objects.equals(registrant, that.registrant)
                && Objects.equals(netName, that.netName)
                && Objects.equals(descriptions, that.descriptions)
                && Objects.equals(adminContacts, that.adminContacts)
                && Objects.equals(techContacts, that.techContacts)
                && Objects.equals(abuseContacts, that.abuseContacts)
                && Objects.equals(rawWhoisOutput, that.rawWhoisOutput);
    }

    @Override
    public int hashCode() {
        return Objects.hash(
                cidr,
                allCidrs,
                ipRange,
                matchedIpAddresses,
                country,
                registrant,
                netName,
                descriptions,
                adminContacts,
                techContacts,
                abuseContacts,
                rawWhoisOutput);
    }

    @Override
    public String toString() {
        return "WhoisCidrInfo{" +
                "cidr=" + cidr +
                ", allCidrs=" + allCidrs +
                ", ipRange='" + ipRange + '\'' +
                ", matchedIpAddresses=" + matchedIpAddresses +
                ", country='" + country + '\'' +
                ", registrant='" + registrant + '\'' +
                ", netName='" + netName + '\'' +
                ", descriptions=" + descriptions +
                ", adminContacts=" + adminContacts +
                ", techContacts=" + techContacts +
                ", abuseContacts=" + abuseContacts +
                '}';
    }
}

