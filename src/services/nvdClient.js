const axios = require("axios");
const dayjs = require("dayjs");
const config = require("../config");

const client = axios.create({
  baseURL: config.nvdApiBaseUrl,
  timeout: 30000,
  headers: config.nvdApiKey
    ? {
        apiKey: config.nvdApiKey
      }
    : {}
});

async function fetchCvesPage(params) {
  const response = await client.get("", { params });
  return response.data;
}

function chooseMetric(metrics = {}) {
  const candidates = [
    { key: "cvssMetricV40", version: "4.0" },
    { key: "cvssMetricV31", version: "3.1" },
    { key: "cvssMetricV30", version: "3.0" },
    { key: "cvssMetricV2", version: "2.0" }
  ];

  for (const item of candidates) {
    const value = metrics[item.key];
    if (Array.isArray(value) && value.length > 0) {
      const metric = value[0];
      return {
        cvss_version: item.version,
        cvss_score: metric?.cvssData?.baseScore ?? null,
        cvss_severity:
          metric?.cvssData?.baseSeverity || metric?.baseSeverity || null
      };
    }
  }

  return {
    cvss_version: null,
    cvss_score: null,
    cvss_severity: null
  };
}

function extractCpes(configurations = []) {
  const cpes = [];

  const pushCriteria = (match) => {
    const criteria = match?.criteria || match?.cpe23Uri || match?.cpe23uri;
    if (criteria) {
      cpes.push(criteria);
    }
  };

  const walkNodes = (nodes = []) => {
    for (const node of nodes) {
      const cpeMatches = node.cpeMatch || node.cpe_match || [];
      if (Array.isArray(cpeMatches)) {
        for (const match of cpeMatches) {
          pushCriteria(match);
        }
      }

      if (Array.isArray(node.children)) {
        walkNodes(node.children);
      }

      if (Array.isArray(node.nodes)) {
        walkNodes(node.nodes);
      }
    }
  };

  for (const configNode of configurations) {
    const topLevelMatches = configNode.cpeMatch || configNode.cpe_match || [];
    for (const match of topLevelMatches) {
      pushCriteria(match);
    }

    walkNodes(configNode.nodes || []);
  }

  return [...new Set(cpes)];
}

function extractVendorsFromCpes(cpes = []) {
  const vendors = new Set();

  for (const cpe of cpes) {
    const parts = cpe.split(":");
    if (parts.length > 4 && parts[3] && parts[3] !== "*") {
      vendors.add(parts[3]);
    }
  }

  return [...vendors].sort();
}

function extractCwe(weaknesses = []) {
  const values = [];
  for (const weakness of weaknesses) {
    for (const desc of weakness.description || []) {
      if (desc.value && !desc.value.toLowerCase().includes("noinfo")) {
        values.push(desc.value);
      }
    }
  }
  return [...new Set(values)];
}

function normalizeVulnerability(vulnerability) {
  const cve = vulnerability.cve || {};
  const descriptions = cve.descriptions || [];
  const descEn = descriptions.find((d) => d.lang === "en")?.value || "";

  if (descEn.toUpperCase().includes("REJECT")) {
    return null;
  }

  const cpes = extractCpes(cve.configurations || []);
  const vendors = extractVendorsFromCpes(cpes);
  const metric = chooseMetric(cve.metrics || {});
  const cweList = extractCwe(cve.weaknesses || []);

  return {
    cve_id: cve.id,
    description: descEn,
    published_date: cve.published,
    last_modified_date: cve.lastModified,
    cvss_version: metric.cvss_version,
    cvss_score: metric.cvss_score,
    cvss_severity: metric.cvss_severity,
    cwe: cweList.join(", "),
    vendors: JSON.stringify(vendors),
    cpes: JSON.stringify(cpes),
    references_json: JSON.stringify(cve.references || []),
    source_identifier: cve.sourceIdentifier || "",
    raw_json: JSON.stringify(vulnerability)
  };
}

async function fetchUpdatedCves({ lastSyncDate, maxResultsPerPage = 2000 }) {
  const endDate = dayjs().toISOString();
  const startDate = lastSyncDate;

  let startIndex = 0;
  let totalResults = 0;
  const allNormalized = [];

  do {
    const data = await fetchCvesPage({
      lastModStartDate: startDate,
      lastModEndDate: endDate,
      startIndex,
      resultsPerPage: maxResultsPerPage
    });

    const vulnerabilities = data.vulnerabilities || [];
    totalResults = data.totalResults || 0;

    for (const item of vulnerabilities) {
      const normalized = normalizeVulnerability(item);
      if (normalized) {
        allNormalized.push(normalized);
      }
    }

    startIndex += maxResultsPerPage;
  } while (startIndex < totalResults);

  return {
    startDate,
    endDate,
    totalResults,
    records: allNormalized
  };
}

module.exports = {
  fetchUpdatedCves
};
