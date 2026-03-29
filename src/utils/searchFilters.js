function parseSearchFilters(query, defaults = {}) {
  const page = Math.max(1, Number(query.page) || defaults.page || 1);
  const pageSize = Math.min(
    defaults.maxPageSize || 100,
    Math.max(1, Number(query.pageSize) || defaults.pageSize || 20)
  );

  const cvssMinRaw = query.cvssMin;
  const cvssMaxRaw = query.cvssMax;

  const cvssMin =
    cvssMinRaw !== undefined && cvssMinRaw !== ""
      ? Number(cvssMinRaw)
      : undefined;
  const cvssMax =
    cvssMaxRaw !== undefined && cvssMaxRaw !== ""
      ? Number(cvssMaxRaw)
      : undefined;

  return {
    keyword: query.keyword?.trim(),
    vendor: query.vendor?.trim(),
    cwe: query.cwe?.trim(),
    severity: query.severity?.trim(),
    year: query.year,
    cvssMin,
    cvssMax,
    page,
    pageSize
  };
}

module.exports = {
  parseSearchFilters
};
