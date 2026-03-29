# CVE Intel Hub

He thong tra cuu va phan tich CVE su dung NVD API, ho tro SQLite/PostgreSQL, Redis cache, va export CSV/PDF.

## 1. Chuc nang
- Dong bo CVE tu NVD theo lich.
- Tra cuu theo CVE ID.
- Tim kiem/loc theo keyword, vendor, CWE, CVSS, nam.
- Xem chi tiet CVE: mo ta, CVSS, CPE, tham chieu.
- Thong ke tong quan theo nam va muc do.
- Cache ket qua search bang Redis de giam tai DB khi du lieu lon.
- Export ket qua loc ra CSV va PDF.
- Dashboard phan tich: severity, top vendor, top CWE, ti le rui ro cao.
- Luu lich su dong bo CVE de theo doi van hanh.

## 2. Cong nghe
- Node.js + Express
- SQLite (better-sqlite3) hoac PostgreSQL (pg)
- Redis (optional, cho search cache)
- PDFKit (xuat PDF)
- EJS + CSS responsive
- node-cron cho scheduler

## 3. Cai dat va chay
```bash
npm install
copy .env.example .env
npm run start
```

Server mac dinh: http://localhost:3000

## 4. Dong bo du lieu CVE
### Cach 1: Dong bo thu cong
```bash
npm run sync
```

### Cach 2: Dong bo tu dong
Khi server khoi dong, scheduler se chay theo `SYNC_CRON` (mac dinh moi 6 gio).

## 5. API chinh
### Tim kiem CVE
```http
GET /api/search?keyword=windows&severity=HIGH&vendor=microsoft&year=2025&cvssMin=7
```

Ket qua co cache Redis theo bo loc (`SEARCH_CACHE_TTL_SECONDS`).

### Xem chi tiet
```http
GET /api/cve/CVE-2025-1234
```

### Thong ke
```http
GET /api/stats
```

### Thong ke nang cao
```http
GET /api/stats/advanced
```

### Lich su dong bo
```http
GET /api/sync/history?limit=20
```

### Export CSV
```http
GET /api/export/csv?keyword=windows&severity=HIGH&vendor=microsoft
```

### Export PDF
```http
GET /api/export/pdf?keyword=windows&severity=HIGH&vendor=microsoft
```

### Trigger sync
```http
POST /api/sync
```

## 6. Cac bien moi truong
- `PORT`: cong server.
- `NVD_API_BASE_URL`: endpoint NVD CVE 2.0.
- `NVD_API_KEY`: API key NVD (khuyen nghi).
- `SYNC_CRON`: lich cron, vi du `0 */6 * * *`.
- `INITIAL_SYNC_DAYS`: so ngay lui de sync lan dau.
- `DB_CLIENT`: `sqlite` hoac `postgres`.
- `DB_PATH`: duong dan file SQLite (chi dung khi `DB_CLIENT=sqlite`).
- `POSTGRES_URL`: connection string PostgreSQL (chi dung khi `DB_CLIENT=postgres`).
- `POSTGRES_SSL`: `true/false` cho ket noi PostgreSQL.
- `REDIS_URL`: connection string Redis, de trong neu khong dung cache.
- `SEARCH_CACHE_TTL_SECONDS`: thoi gian cache ket qua search.
- `EXPORT_MAX_ROWS`: gioi han so dong khi export.

## 7. Cau truc thu muc
- `src/app.js`: khoi tao server.
- `src/services/nvdClient.js`: goi NVD API va normalize du lieu.
- `src/services/syncService.js`: dong bo va cap nhat lastSyncDate.
- `src/repositories/sqliteCveRepository.js`: query/upsert voi SQLite.
- `src/repositories/postgresCveRepository.js`: query/upsert voi PostgreSQL.
- `src/services/cacheService.js`: Redis cache cho search.
- `src/routes/api.js`: endpoint API JSON.
- `src/routes/web.js`: giao dien web.

## 8. Luu y trien khai
- Nen su dung NVD API key de tranh rate limit.
- Khi can scale nhieu user dong thoi, dat `DB_CLIENT=postgres` va cau hinh `POSTGRES_URL`.
- Neu bat Redis, cache `/search` va `/api/search` se tu dong hoat dong.
- UI da co nut export nhanh CSV/PDF tu bo loc hien tai.

## 9. Trien khai Vercel
- Da cau hinh serverless entrypoint tai `api/index.js` va `vercel.json`.
- Khuyen nghi dung `DB_CLIENT=postgres` tren Vercel de co du lieu ben vung.
- Neu de `DB_CLIENT=sqlite`, he thong se dung `/tmp/cves.db` (du lieu tam thoi, mat sau moi lan cold start/redeploy).
- Khong set `DB_PATH=./data/cves.db` tren Vercel (read-only, gay loi ENOENT/mkdir `/var/task/data`).
- Can set env tren Vercel:
	- `DB_CLIENT=postgres`
	- `POSTGRES_URL=<your-postgres-connection-string>`
	- `POSTGRES_SSL=true` (neu nha cung cap yeu cau SSL)
	- `NVD_API_KEY=<your-key>` (khuyen nghi)
