const express = require("express");
const {
  searchCves,
  getCveById,
  getStats,
  getAdvancedStats,
  listSyncHistory
} = require("../repositories");
const config = require("../config");
const { parseSearchFilters } = require("../utils/searchFilters");
const {
  getJson,
  setJson,
  makeSearchCacheKey
} = require("../services/cacheService");

const router = express.Router();

function asyncHandler(fn) {
  return (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
}

async function getCachedSearchResult(filters) {
  const cacheKey = makeSearchCacheKey(filters);
  const cached = await getJson(cacheKey);
  if (cached) {
    return cached;
  }

  const result = await searchCves(filters);
  await setJson(cacheKey, result, config.searchCacheTtlSeconds);
  return result;
}

function buildMitigation(cve) {
  const severity = (cve.cvss_severity || "UNKNOWN").toUpperCase();
  const cweText = (cve.cwe || "").toUpperCase();
  const desc = (cve.description || "").toLowerCase();
  const score = Number.isFinite(cve.cvss_score) ? cve.cvss_score : null;
  const refs = cve.references || [];

  const exploitKeywords = ["exploit", "poc", "metasploit", "rce", "proof-of-concept"];
  const hasExploitSignal = refs.some((ref) => {
    const text = `${ref.url || ""} ${ref.tags || ""}`.toLowerCase();
    return exploitKeywords.some((keyword) => text.includes(keyword));
  });

  const vulnProfiles = [
    {
      key: "command-injection",
      title: "Command Injection",
      match: cweText.includes("CWE-78") || cweText.includes("CWE-77") || desc.includes("command injection"),
      actions: [
        "Không thực thi shell với dữ liệu người dùng; thay bằng API gọi process an toàn và truyền tham số dạng mảng.",
        "Áp dụng allowlist cho input và chặn metacharacter nguy hiểm (&, |, ;, $, `, >, <).",
        "Chạy service với quyền tối thiểu để giảm tác động nếu bị khai thác."
      ]
    },
    {
      key: "sql-injection",
      title: "SQL Injection",
      match: cweText.includes("CWE-89") || desc.includes("sql injection"),
      actions: [
        "Dùng prepared statement/parameterized query cho toàn bộ truy vấn.",
        "Kiểm tra đầu vào ở tầng API và từ chối payload bất thường.",
        "Bật audit log với câu truy vấn lỗi để phát hiện thử khai thác."
      ]
    },
    {
      key: "xss",
      title: "Cross-Site Scripting",
      match: cweText.includes("CWE-79") || desc.includes("cross-site scripting") || desc.includes("xss"),
      actions: [
        "Encode output theo đúng context (HTML/attribute/JS).",
        "Bật CSP chặt chẽ và vô hiệu inline script không cần thiết.",
        "Rà soát các điểm render dữ liệu người dùng ra giao diện."
      ]
    },
    {
      key: "path-traversal",
      title: "Path Traversal",
      match: cweText.includes("CWE-22") || desc.includes("path traversal"),
      actions: [
        "Chuẩn hóa đường dẫn và chặn `..`/đường dẫn tuyệt đối từ input.",
        "Giới hạn truy cập file theo thư mục cho phép cố định.",
        "Tách user runtime khỏi dữ liệu nhạy cảm bằng sandbox/chroot/container."
      ]
    },
    {
      key: "memory-corruption",
      title: "Memory Corruption",
      match: cweText.includes("CWE-787") || cweText.includes("CWE-125") || cweText.includes("CWE-416") || desc.includes("heap") || desc.includes("buffer overflow"),
      actions: [
        "Ưu tiên cập nhật phiên bản chứa bản vá do nguy cơ thực thi mã từ xa.",
        "Bật cơ chế bảo vệ runtime (ASLR/DEP/CFG) nếu nền tảng hỗ trợ.",
        "Theo dõi crash dump và traffic bất thường sau khi triển khai bản vá."
      ]
    },
    {
      key: "dos",
      title: "Denial of Service",
      match: cweText.includes("CWE-400") || cweText.includes("CWE-770") || desc.includes("denial of service") || desc.includes("out-of-memory"),
      actions: [
        "Thiết lập rate limiting và giới hạn tài nguyên theo request/session.",
        "Đặt ngưỡng timeout, circuit breaker và autoscaling phù hợp.",
        "Theo dõi CPU/RAM để cảnh báo sớm trước khi service gián đoạn."
      ]
    }
  ];

  const matchedProfiles = vulnProfiles.filter((profile) => profile.match);
  const profileTitles = matchedProfiles.length
    ? matchedProfiles.map((profile) => profile.title)
    : ["Chung/không xác định rõ loại lỗi"];
  const hasPatchRef = (cve.references || []).some((ref) => {
    const url = (ref.url || "").toLowerCase();
    return url.includes("patch") || url.includes("commit") || url.includes("release") || url.includes("advisor");
  });

  const severityPlan = {
    priority: "Thấp",
    eta: "Theo chu kỳ bảo trì",
    summary: "Theo dõi trong backlog hardening và đánh giá lại khi có thay đổi hệ thống.",
    actions: []
  };

  if (severity === "CRITICAL" || severity === "HIGH") {
    severityPlan.priority = "Rất cao";
    severityPlan.eta = "Trong 24-72 giờ";
    severityPlan.summary = "Ưu tiên xử lý ngay để giảm nguy cơ bị khai thác thực tế.";
    severityPlan.actions.push(
      "Xác định toàn bộ máy chủ/service đang dùng phiên bản bị ảnh hưởng và cô lập bề mặt tấn công bên ngoài.",
      "Áp dụng bản vá hoặc nâng phiên bản theo advisory/reference chính thức.",
      "Bật giám sát log và cảnh báo bất thường cho endpoint/chức năng liên quan trong 7 ngày sau khi vá."
    );
  } else if (severity === "MEDIUM") {
    severityPlan.priority = "Trung bình";
    severityPlan.eta = "Trong sprint gần nhất";
    severityPlan.summary = "Lên kế hoạch vá sớm, đồng thời áp dụng giảm thiểu tạm thời.";
    severityPlan.actions.push(
      "Đưa vào kế hoạch phát hành gần nhất và kiểm thử hồi quy chức năng bị ảnh hưởng.",
      "Giới hạn quyền truy cập theo IP/VPN/WAF cho các endpoint nhạy cảm.",
      "Theo dõi nguồn công bố exploit để nâng mức ưu tiên nếu có PoC công khai."
    );
  } else if (severity === "LOW" || severity === "NONE") {
    severityPlan.priority = "Thấp";
    severityPlan.eta = "Theo chu kỳ bảo trì";
    severityPlan.summary = "Xử lý theo lịch hardening định kỳ, ưu tiên thấp hơn các lỗi điểm cao.";
    severityPlan.actions.push(
      "Gộp xử lý cùng đợt nâng cấp phụ thuộc định kỳ.",
      "Bổ sung test bảo mật hồi quy để tránh tái phát.",
      "Giữ theo dõi CVE này để cập nhật nếu severity thay đổi."
    );
  } else {
    severityPlan.priority = "Chưa xác định";
    severityPlan.eta = "Đánh giá thủ công";
    severityPlan.summary = "Nguồn dữ liệu chưa có CVSS đầy đủ, cần đánh giá theo bối cảnh hệ thống.";
    severityPlan.actions.push(
      "Đánh giá mức phơi nhiễm: service có public ra Internet hay chỉ nội bộ.",
      "Kiểm tra thành phần bị ảnh hưởng có đang được bật trong môi trường thực tế hay không.",
      "Thiết lập kiểm soát tạm thời (network policy, rate limit, auth cứng hơn) cho tới khi có patch."
    );
  }

  if (score !== null) {
    if (score >= 9) {
      severityPlan.eta = "Xử lý khẩn cấp trong 24 giờ";
    } else if (score >= 7) {
      severityPlan.eta = "Xử lý trong 24-72 giờ";
    }
  }

  const groupActions = [];
  for (const profile of matchedProfiles) {
    groupActions.push(...profile.actions);
  }

  if (!matchedProfiles.length) {
    groupActions.push("Chưa xác định rõ nhóm lỗi từ CWE/description; áp dụng hardening chung và theo dõi cập nhật từ vendor.");
  }

  if (hasExploitSignal) {
    severityPlan.priority = "Khẩn cấp";
    severityPlan.actions.unshift("Có tín hiệu exploit/PoC: ưu tiên bật rule chặn tạm thời (WAF/IPS/ACL) trước khi vá.");
  }

  if (!hasPatchRef) {
    severityPlan.actions.push("Chưa thấy link patch rõ ràng: ưu tiên theo dõi issue/release note của vendor để cập nhật bản vá chính thức.");
  }

  severityPlan.actions = [...new Set(severityPlan.actions)];

  return {
    priority: severityPlan.priority,
    eta: severityPlan.eta,
    summary: severityPlan.summary,
    actions: severityPlan.actions,
    profiles: profileTitles,
    exploitSignal: hasExploitSignal ? "Có dấu hiệu PoC/Exploit" : "Chưa thấy dấu hiệu PoC rõ ràng",
    severityPlan,
    groupPlan: {
      profiles: profileTitles,
      actions: [...new Set(groupActions)]
    }
  };
}

router.get("/", asyncHandler(async (req, res) => {
  const filters = parseSearchFilters(req.query, {
    page: 1,
    pageSize: 15,
    maxPageSize: 50
  });
  const result = await getCachedSearchResult(filters);

  res.render("index", {
    query: req.query,
    result,
    severityOptions: ["LOW", "MEDIUM", "HIGH", "CRITICAL", "NONE", "UNKNOWN"]
  });
}));

router.get("/detail/:id", asyncHandler(async (req, res) => {
  const cve = await getCveById(req.params.id);
  if (!cve) {
    return res.status(404).render("not-found", {
      cveId: req.params.id
    });
  }

  return res.render("detail", {
    cve,
    mitigation: buildMitigation(cve)
  });
}));

router.get("/dashboard", asyncHandler(async (req, res) => {
  const [stats, advanced, syncHistory] = await Promise.all([
    getStats(),
    getAdvancedStats(),
    listSyncHistory(10)
  ]);

  res.render("dashboard", {
    stats,
    advanced,
    syncHistory
  });
}));

module.exports = router;
