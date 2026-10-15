import datetime
import hashlib
import ipaddress
import re
import socket
import ssl
import time
import uuid

import dns.resolver
import requests

# Some internal DNS views (this scanner's own vantage point included) return a mix of
# private and public A records for the same public hostname. socket.getaddrinfo() tries
# them in order, and an unreachable private address before the real public one adds a
# full connect-timeout of dead time per request. Prefer public addresses when both exist.
_orig_getaddrinfo = socket.getaddrinfo


def _public_preferring_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
    results = _orig_getaddrinfo(host, port, family, type, proto, flags)
    try:
        public = [r for r in results if not ipaddress.ip_address(r[4][0]).is_private]
    except ValueError:
        public = []
    return public if public else results


socket.getaddrinfo = _public_preferring_getaddrinfo

USER_AGENT = "Mozilla/5.0 (CI-Watch Internal VA Scanner; Tzu Chi Hospital Tech Security)"

DEFAULT_SENSITIVE_PATHS = [
    "/.env", "/.git/config", "/.git/HEAD", "/config.php.bak", "/phpinfo.php",
    "/backup/", "/uploads/", "/admin", "/administrator", "/wp-login.php",
    "/wp-admin/", "/wp-content/", "/wp-json/", "/.well-known/security.txt",
    "/server-status", "/xmlrpc.php", "/.htaccess", "/web.config",
    "/composer.json", "/package.json", "/vendor/", "/storage/logs/laravel.log",
    "/.DS_Store",
    "/internal", "/staff", "/intranet", "/employee", "/login-internal",
    "/dashboard-internal", "/console", "/management", "/backend-admin",
    "/hr", "/portal-internal", "/debug", "/swagger", "/swagger-ui",
    "/graphql", "/actuator", "/actuator/health", "/_profiler",
    "/telescope", "/elmah.axd", "/api/debug", "/test", "/dev", "/staging",
]

CONTENT_SIGNATURES = {
    "secrets": [
        r"AKIA[0-9A-Z]{16}",
        r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----",
        r"DB_PASSWORD\s*=\s*['\"]?\S",
        r"(api|secret)_key['\"]?\s*[:=]\s*['\"][A-Za-z0-9_\-]{12,}",
    ],
    "source_code": [
        r"<\?php",
        r"^\s*(import|from)\s+[\w.]+\s+(import|from)?\s*['\"a-zA-Z]",
        r"require\(['\"]",
        r"^\s*def\s+\w+\(.*\):",
        r"^#!/usr/bin/env",
        r"class\s+\w+\s*[:{(]",
        r"SELECT\s+.+\s+FROM\s+\w+",
    ],
    "directory_listing": [r"Index of /", r"<title>Index of"],
    "error_trace": [
        r"Traceback \(most recent call last\)",
        r"Fatal error:",
        r"Warning: include",
        r"Stack trace:",
        r"at Object\.<anonymous>",
    ],
}


def classify_content(text):
    matched = []
    for category, patterns in CONTENT_SIGNATURES.items():
        for pattern in patterns:
            if re.search(pattern, text, re.MULTILINE):
                matched.append(category)
                break
    return matched

DEFAULT_HEADER_PATHS = ["/", "/en", "/en/about", "/testimony", "/en/promo"]

SECURITY_HEADERS = [
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
]
# HSTS gets its own dedicated check_hsts()/analyze_hsts_findings() below
# (it needs to inspect the header's directives and the HTTP->HTTPS redirect
# behavior, not just presence/absence) — kept out of SECURITY_HEADERS so it
# isn't also flagged by the generic missing-header check and double-reported.

INFO_DISCLOSURE_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version", "X-Generator"]

EXPLANATIONS = {
    "dns_public_private_leak": {
        "apa_itu": "DNS adalah 'buku telepon' internet yang menerjemahkan nama domain (tzuchihospital.co.id) menjadi alamat IP server. Idealnya, publik hanya boleh melihat IP server yang memang untuk publik.",
        "fungsi": "Memastikan siapa pun di internet yang mencari domain ini diarahkan ke server yang benar dan aman untuk diakses dari luar.",
        "dampak": "Kalau publik bisa melihat IP internal (10.x/192.168.x), itu artinya peta jaringan internal RS bocor ke siapa saja di internet — mempermudah penyerang menargetkan server internal secara langsung.",
    },
    "dns_split_horizon_info": {
        "apa_itu": "Ini bukan masalah — hanya perbedaan jawaban DNS tergantung dari mana pertanyaan itu berasal (dari dalam jaringan RS vs dari internet umum). Ini disebut split-horizon DNS dan memang lazim dipakai perusahaan.",
        "fungsi": "Staf di jaringan internal diarahkan ke jalur internal (lebih cepat/aman), sementara publik diarahkan ke jalur publik.",
        "dampak": "Tidak ada dampak keamanan — sudah dikonfirmasi publik tidak melihat IP internal ini.",
    },
    "spf_missing": {
        "apa_itu": "SPF (Sender Policy Framework) adalah daftar resmi 'server mana saja yang boleh mengirim email atas nama domain ini'.",
        "fungsi": "Supaya penyedia email penerima (Gmail, Outlook, dll) bisa cek: pengirim ini beneran terdaftar sebagai pengirim resmi RS, atau bukan.",
        "dampak": "Tanpa SPF, siapa pun bisa mengirim email yang seolah-olah dari '@tzuchihospital.co.id' dan lebih mudah lolos ke inbox korban — biasa dipakai untuk phishing ke pasien/staf/mitra.",
    },
    "spf_softfail": {
        "apa_itu": "SPF sudah ada, tapi aturannya diset 'soft-fail' (~all) — artinya email dari pengirim tak terdaftar tetap ditandai mencurigakan tapi TETAP diteruskan ke inbox, bukan ditolak.",
        "fungsi": "SPF seharusnya membantu memfilter pengirim palsu secara tegas.",
        "dampak": "Karena masih soft-fail, email spoofing (mengatasnamakan domain RS) punya peluang lebih besar tetap sampai ke korban dibanding kalau pakai hard-fail (-all).",
    },
    "spf_no_strict": {
        "apa_itu": "SPF ada tapi tidak diakhiri aturan tegas.",
        "fungsi": "Menentukan sikap tegas terhadap pengirim yang tidak terdaftar.",
        "dampak": "Efektivitas SPF dalam mencegah email spoofing jadi berkurang.",
    },
    "dmarc_missing": {
        "apa_itu": "DMARC adalah aturan yang memberi tahu server email lain apa yang harus dilakukan kalau ada email mengaku dari domain kita tapi gagal verifikasi keaslian (gagal cek SPF/DKIM).",
        "fungsi": "Mencegah orang lain memalsukan email seolah dari '@tzuchihospital.co.id' (email spoofing) — biasanya untuk phishing ke pasien, staf, atau mitra RS.",
        "dampak": "Tanpa DMARC, email palsu yang mengatasnamakan RS punya peluang besar tetap masuk ke inbox penerima seolah asli — bisa dipakai penipu untuk minta transfer, minta data pasien, dll memakai nama baik rumah sakit.",
    },
    "dmarc_p_none": {
        "apa_itu": "DMARC sudah ada, tapi policy-nya 'p=none' — artinya sistem cuma MEMANTAU dan melaporkan email mencurigakan, tidak benar-benar memblokir/mengarantina.",
        "fungsi": "Idealnya DMARC dipakai untuk menolak atau mengkarantina email palsu, bukan cuma dicatat.",
        "dampak": "Email spoofing yang mengatasnamakan domain RS tetap bisa sampai normal ke inbox korban — perlindungan yang ada saat ini baru sebatas 'pemantauan', belum benar-benar mencegah.",
    },
    "dmarc_p_quarantine": {
        "apa_itu": "DMARC sudah aktif menahan (karantina/masuk folder spam) email yang gagal verifikasi, sudah lebih baik dari p=none tapi belum full-block.",
        "fungsi": "Mengurangi kemungkinan email palsu sampai ke inbox utama korban.",
        "dampak": "Risiko sudah berkurang, tapi email palsu masih berpotensi lolos di beberapa penyedia email yang tidak strict menjalankan kebijakan quarantine.",
    },
    "Strict-Transport-Security": {
        "apa_itu": "HSTS adalah instruksi dari website ke browser: 'selalu akses saya lewat HTTPS, jangan pernah pakai HTTP biasa, walau user ketik http:// atau klik link lama'.",
        "fungsi": "Mencegah browser 'kejebak' memakai koneksi HTTP yang tidak terenkripsi, terutama saat pertama kali connect di jaringan publik/WiFi yang tidak dipercaya.",
        "dampak": "Tanpa header ini, penyerang yang satu jaringan dengan korban (misal WiFi publik/kafe) berpotensi melakukan downgrade attack — mengarahkan user ke versi HTTP agar bisa menyadap atau mengubah data yang dikirim (termasuk sesi login).",
    },
    "Content-Security-Policy": {
        "apa_itu": "CSP adalah daftar aturan 'script/konten dari sumber mana saja yang boleh dijalankan di halaman ini'.",
        "fungsi": "Sebagai lapisan pertahanan tambahan: kalau suatu saat ada celah XSS (penyerang berhasil menyisipkan script jahat), CSP membuat script itu tetap gagal dijalankan karena sumbernya tidak diizinkan.",
        "dampak": "Tanpa CSP, dampak dari celah XSS (kalau nanti ditemukan) bisa jauh lebih parah — mulai dari pencurian sesi login pengguna sampai halaman dialihkan ke situs phishing.",
    },
    "X-Frame-Options": {
        "apa_itu": "Header yang menentukan apakah halaman ini boleh ditampilkan di dalam frame/iframe website lain.",
        "fungsi": "Mencegah teknik 'clickjacking' — situs jahat menumpuk halaman asli RS secara tak terlihat lalu menipu user supaya tanpa sadar mengklik sesuatu di halaman asli.",
        "dampak": "Tanpa header ini, halaman berpotensi disalahgunakan untuk menipu pengguna melakukan aksi tanpa disadari (misal submit form tertentu).",
    },
    "X-Content-Type-Options": {
        "apa_itu": "Header yang memberi tahu browser: 'jangan coba menebak sendiri tipe file ini, ikuti Content-Type yang sudah saya tentukan'.",
        "fungsi": "Mencegah browser salah mengira suatu file (misalnya file yang diupload user) sebagai script yang bisa dieksekusi.",
        "dampak": "Tanpa header ini, ada celah kecil untuk serangan MIME-sniffing yang berpotensi memicu eksekusi script yang tidak diinginkan.",
    },
    "info_disclosure": {
        "apa_itu": "Header respons yang otomatis dikirim server dan menyebutkan teknologi/software yang dipakai di baliknya (misalnya 'Next.js', 'nginx').",
        "fungsi": "Header ini bukan fitur keamanan — hanya informasi teknis default dari server/framework.",
        "dampak": "Bukan bug langsung, tapi memberi 'peta awal' ke penyerang soal teknologi yang dipakai, sehingga mereka bisa lebih cepat mencari celah keamanan spesifik untuk teknologi tersebut.",
    },
    "sensitive_path_exposed": {
        "apa_itu": "File atau folder yang seharusnya TIDAK bisa diakses publik (misalnya file konfigurasi berisi password, source code, backup database) ternyata bisa dibuka langsung lewat browser.",
        "fungsi": "Bukan fitur — ini murni kesalahan konfigurasi server/deployment.",
        "dampak": "Kalau isi file ini beneran sensitif (misal .env berisi kredensial database), penyerang bisa langsung dapat akses ke sistem backend tanpa perlu teknik hacking rumit. Ini termasuk kategori temuan paling berbahaya.",
    },
    "error_5xx_pattern": {
        "apa_itu": "Server merespons dengan kode error 5xx (kesalahan di sisi server) pada beberapa path yang diuji, bukan 403 (ditolak)/404 (tidak ada) seperti biasanya.",
        "fungsi": "Perlu dipastikan apakah ini WAF/proteksi otomatis yang sengaja memblokir (baik), atau aplikasi yang error/crash (perlu diperbaiki).",
        "dampak": "Kalau ternyata aplikasi crash (bukan WAF), bisa jadi indikasi bug yang berpotensi disalahgunakan, atau risiko downtime/pengalaman pengguna terganggu.",
    },
    "tls_legacy": {
        "apa_itu": "TLS adalah protokol enkripsi yang melindungi data yang lewat antara browser pengguna dan server (supaya orang di tengah jaringan tidak bisa membaca/mengubah data).",
        "fungsi": "Menjaga kerahasiaan dan keutuhan data (login, data pasien, dll) saat dikirim lewat internet.",
        "dampak": "Versi TLS lawas (1.0/1.1/SSLv3) punya celah keamanan yang sudah diketahui publik — penyerang di jaringan yang sama berpotensi membongkar enkripsi ini.",
    },
    "tls_1_2": {
        "apa_itu": "TLS 1.2 masih tergolong aman dan umum dipakai, tapi bukan versi terbaru.",
        "fungsi": "Sama seperti TLS pada umumnya — mengenkripsi data yang lewat.",
        "dampak": "Risiko saat ini rendah, tapi TLS 1.3 memberikan performa dan keamanan lebih baik (lebih sedikit celah known-vulnerability jangka panjang).",
    },
    "cert_expiring": {
        "apa_itu": "Sertifikat SSL/TLS adalah 'identitas resmi' website yang diterbitkan otoritas terpercaya (CA) dan punya masa berlaku.",
        "fungsi": "Membuktikan ke browser dan pengguna bahwa website ini benar milik tzuchihospital.co.id, bukan situs tiruan.",
        "dampak": "Kalau sampai expired, browser akan menampilkan peringatan 'Tidak Aman' atau bahkan memblokir akses sama sekali — bisa membuat pasien/pengguna panik dan menurunkan kepercayaan, plus membiasakan user 'klik lanjut saja' pada warning yang suatu saat bisa dimanfaatkan situs phishing sungguhan.",
    },
    "sensitive_path_secrets": {
        "apa_itu": "Scanner mendeteksi pola yang mirip kredensial asli (API key, password, private key) langsung di isi halaman yang bisa diakses publik.",
        "fungsi": "Kredensial seperti ini seharusnya tidak pernah ada di file yang bisa diakses browser — biasanya tersimpan di environment variable atau secret manager yang tidak publik.",
        "dampak": "Ini setara memberi kunci masuk ke sistem RS ke siapa pun yang menemukan path ini. Penyerang bisa langsung pakai kredensial tersebut untuk akses database, API, atau layanan cloud tanpa perlu hacking lebih lanjut.",
    },
    "sensitive_path_source_code": {
        "apa_itu": "Isi file yang diambil dari path ini terdeteksi berupa kode program mentah (source code) — bukan halaman website biasa yang sudah 'jadi' untuk pengunjung.",
        "fungsi": "Source code mestinya cuma bisa diakses developer lewat repository internal, bukan lewat browser publik.",
        "dampak": "Kode sumber bisa membocorkan logika bisnis, cara sistem bekerja, celah keamanan yang belum diperbaiki, bahkan kadang kredensial yang ditulis langsung di kode (hardcoded). Ini mempermudah penyerang merancang serangan yang lebih presisi.",
    },
    "directory_listing": {
        "apa_itu": "Alih-alih menampilkan halaman website, server menampilkan daftar seluruh file/folder yang ada di direktori tersebut (seperti membuka File Explorer dari browser).",
        "fungsi": "Ini fitur bawaan web server (Apache/nginx) yang seharusnya dimatikan di folder yang tidak dimaksudkan untuk dilihat publik.",
        "dampak": "Pengunjung bisa melihat dan mengunduh semua file di folder itu, termasuk file yang tidak sengaja ter-upload ke sana (backup, dokumen internal, dll) — bahkan file yang namanya tidak pernah dipublikasikan di mana pun.",
    },
    "error_trace_exposed": {
        "apa_itu": "Halaman menampilkan pesan error teknis lengkap (stack trace) alih-alih pesan error yang sudah 'dirapikan' untuk pengguna biasa.",
        "fungsi": "Stack trace berguna untuk developer saat development, tapi seharusnya disembunyikan dari publik saat aplikasi sudah live (production).",
        "dampak": "Stack trace sering membocorkan nama file internal, struktur folder server, versi library yang dipakai, bahkan kadang query database — semua ini mempermudah penyerang memetakan cara menyerang sistem.",
    },
    "sourcemap_exposed": {
        "apa_itu": "Source map (.map) adalah file 'peta' yang menghubungkan kode JavaScript yang sudah diringkas/disamarkan (minified) di production kembali ke kode aslinya yang mudah dibaca — normalnya hanya dipakai developer untuk debugging.",
        "fungsi": "Harusnya file ini tidak ikut ter-deploy ke server production, atau kalaupun ada, tidak boleh bisa diakses publik.",
        "dampak": "Kalau file .map bisa diakses publik, siapa pun bisa 'membongkar' aplikasi web jadi kode aslinya lengkap dengan nama variabel, komentar developer, bahkan kadang API key atau endpoint internal yang tertulis di kode front-end.",
    },
    "hsts_disabled": {
        "apa_itu": "Header HSTS ada, tapi nilainya 'max-age=0' — ini instruksi eksplisit ke browser untuk MELUPAKAN kewajiban HTTPS-only pada domain ini.",
        "fungsi": "max-age=0 dipakai khusus untuk mencabut HSTS (misalnya saat migrasi), bukan untuk dipakai permanen di production.",
        "dampak": "Browser yang sudah pernah menerima max-age=0 ini akan berhenti memaksa HTTPS untuk domain ini, membuka kembali celah downgrade attack yang seharusnya sudah dicegah HSTS.",
    },
    "hsts_short_maxage": {
        "apa_itu": "Durasi 'max-age' pada HSTS menentukan berapa lama browser mengingat untuk selalu memakai HTTPS ke domain ini setelah kunjungan pertama.",
        "fungsi": "Semakin panjang durasinya (idealnya 1 tahun / 31536000 detik), semakin lama browser 'ingat' untuk HTTPS-only tanpa perlu mengunjungi ulang.",
        "dampak": "Durasi yang terlalu pendek membuat perlindungan HSTS cepat hilang kalau user tidak mengakses situs ini secara rutin, sehingga risiko downgrade attack muncul lagi lebih cepat.",
    },
    "hsts_missing_subdomains": {
        "apa_itu": "Directive 'includeSubDomains' pada HSTS memperluas aturan HTTPS-only ke semua subdomain, bukan cuma domain utama.",
        "fungsi": "Memastikan subdomain (misal portal.domain, mail.domain) juga tidak bisa diakses lewat HTTP biasa.",
        "dampak": "Tanpa includeSubDomains, subdomain yang tidak disebutkan tetap rentan downgrade attack meskipun domain utamanya sudah terlindungi HSTS.",
    },
    "hsts_http_no_redirect": {
        "apa_itu": "Saat diakses lewat http:// (bukan https://), server seharusnya langsung redirect (301/302/308) ke versi https://.",
        "fungsi": "Ini jalur 'first contact' — HSTS hanya berlaku SETELAH browser pernah menerima headernya lewat HTTPS. Kalau entry point HTTP tidak redirect, user yang mengetik/klik link http:// pertama kali tetap kena risiko penuh.",
        "dampak": "Penyerang di jaringan yang sama (WiFi publik/kafe) bisa mencegat koneksi HTTP pertama ini (SSL stripping) sebelum browser korban sempat 'belajar' HSTS-nya domain ini, lalu menyadap/mengubah traffic.",
    },
    "cookie_missing_secure": {
        "apa_itu": "Atribut 'Secure' pada cookie memberi tahu browser: cookie ini hanya boleh dikirim lewat koneksi HTTPS, tidak boleh lewat HTTP biasa.",
        "fungsi": "Mencegah cookie (termasuk cookie sesi login) ikut terkirim kalau ada permintaan yang entah bagaimana jatuh ke HTTP, misalnya saat downgrade attack di jaringan publik.",
        "dampak": "Tanpa Secure, penyerang satu jaringan (WiFi publik) berpotensi menyadap cookie ini kalau browser korban terpancing mengakses versi HTTP, lalu memakainya untuk membajak sesi (session hijacking).",
    },
    "cookie_missing_httponly": {
        "apa_itu": "Atribut 'HttpOnly' pada cookie mencegah cookie tersebut dibaca lewat JavaScript di browser (document.cookie).",
        "fungsi": "Jadi lapisan pertahanan tambahan: kalau suatu saat ada celah XSS di halaman ini, script jahat tetap tidak bisa mencuri isi cookie ini.",
        "dampak": "Tanpa HttpOnly, celah XSS (kalau ada) bisa dipakai untuk mencuri cookie sesi langsung lewat JavaScript, lalu dipakai penyerang untuk login sebagai korban tanpa perlu password.",
    },
    "cookie_samesite_none": {
        "apa_itu": "SameSite mengatur apakah cookie ini ikut dikirim saat request datang dari website lain (cross-site), misalnya saat korban mengklik link dari situs penyerang.",
        "fungsi": "Membatasi agar cookie sesi/auth hanya dikirim untuk navigasi yang wajar dari situs sendiri, bukan dipicu otomatis dari situs pihak ketiga.",
        "dampak": "Kalau SameSite tidak diset tegas (atau diset None), risiko serangan CSRF (Cross-Site Request Forgery) meningkat — situs jahat bisa memicu aksi atas nama korban yang sedang login, tanpa korban sadar.",
    },
    "cookie_long_lived": {
        "apa_itu": "Cookie yang diset dengan Max-Age/Expires jauh ke depan (bukan session cookie yang hilang saat browser ditutup).",
        "fungsi": "Idealnya cookie sesi/login punya umur pendek dan diikat ke idle-timeout di server, supaya sesi yang tidak dipakai lagi tidak bisa dibajak dengan curi cookie lawas.",
        "dampak": "Kalau cookie sesi/auth ini bocor (lewat perangkat yang hilang, browser bersama, atau XSS), penyerang punya jendela waktu yang jauh lebih lama untuk memakainya membajak akun, karena cookie-nya tidak cepat expired.",
    },
    "soft_404": {
        "apa_itu": "Soft-404 adalah saat server menjawab 'halaman tidak ditemukan' tapi dengan status HTTP 200 (seolah berhasil), bukan 404 yang semestinya. Scanner mendeteksinya dengan membandingkan respons path yang diuji terhadap respons path acak yang sengaja dibuat tidak pernah ada — kalau identik, berarti server memang membalas semua path tak dikenal dengan halaman yang sama.",
        "fungsi": "Normalnya, status HTTP dipakai untuk tahu apakah sebuah resource benar-benar ada (200) atau tidak (404/403). Soft-404 merusak asumsi dasar ini.",
        "dampak": "Scanner otomatis apa pun (termasuk CI-Watch sendiri) bisa salah melaporkan banyak 'temuan' path sensitif padahal itu cuma halaman generik yang sama untuk semua path. Ini juga berarti kalau suatu saat ada path yang BENAR-BENAR sensitif dan ter-expose, sinyalnya bisa tenggelam di antara noise false-positive seperti ini — perlu dibedakan manual.",
    },
    "subdomain_surface": {
        "apa_itu": "Subdomain adalah 'cabang' dari domain utama (misalnya patientportal.tzuchihospital.co.id) yang biasanya punya aplikasi/sistem terpisah dengan tingkat keamanan yang bisa berbeda-beda.",
        "fungsi": "Ditemukan lewat catatan publik sertifikat SSL (Certificate Transparency Log) — bukan hasil menebak-nebak, murni data yang memang sudah publik.",
        "dampak": "Semakin banyak subdomain publik yang aktif, semakin luas juga 'pintu masuk' yang harus dijaga keamanannya. Kalau salah satu subdomain (apalagi yang menangani data pasien) lebih lemah keamanannya dibanding domain utama, itu bisa jadi titik masuk penyerang.",
    },
}


def _explain(code):
    return EXPLANATIONS.get(code, {"apa_itu": "-", "fungsi": "-", "dampak": "-"})


def _resolve(domain, rtype, nameserver=None, timeout=5):
    resolver = dns.resolver.Resolver()
    if nameserver:
        resolver.nameservers = [nameserver]
    resolver.timeout = timeout
    resolver.lifetime = timeout
    try:
        answer = resolver.resolve(domain, rtype)
        return [r.to_text().strip('"') for r in answer], None
    except dns.resolver.NXDOMAIN:
        return [], "NXDOMAIN"
    except dns.resolver.NoAnswer:
        return [], "NoAnswer"
    except Exception as e:
        return [], str(e)


def _is_private_ip(ip_str):
    try:
        return ipaddress.ip_address(ip_str).is_private
    except ValueError:
        return False


def run_dns_recon(domain, log):
    log(f"DNS recon start for {domain}")
    views = {}
    for label, ns in [("local", None), ("public_8.8.8.8", "8.8.8.8")]:
        view = {}
        for rtype in ["A", "MX", "NS", "TXT"]:
            values, err = _resolve(domain, rtype, ns)
            view[rtype] = {"values": values, "error": err}
            log(f"  [{label}] {rtype} -> {values if not err else err}")
        dmarc_values, dmarc_err = _resolve(f"_dmarc.{domain}", "TXT", ns)
        view["DMARC"] = {"values": dmarc_values, "error": dmarc_err}
        log(f"  [{label}] DMARC -> {dmarc_values if not dmarc_err else dmarc_err}")
        views[label] = view
    return views


def analyze_dns_findings(views):
    findings = []
    local_a = set(views.get("local", {}).get("A", {}).get("values", []))
    public_a = set(views.get("public_8.8.8.8", {}).get("A", {}).get("values", []))

    public_private_ips = sorted(ip for ip in public_a if _is_private_ip(ip))
    if public_private_ips:
        findings.append({
            "category": "DNS",
            "severity": "Critical",
            "summary": "Public DNS resolver mengembalikan IP privat/internal",
            "evidence": f"A record via 8.8.8.8: {', '.join(public_private_ips)}",
            "recommendation": "Segera audit konfigurasi DNS publik (authoritative NS) — domain publik tidak boleh mengarah ke IP RFC1918.",
            **_explain("dns_public_private_leak"),
        })

    local_only_private = sorted(ip for ip in local_a if _is_private_ip(ip) and ip not in public_a)
    if local_only_private and not public_private_ips:
        findings.append({
            "category": "DNS",
            "severity": "Informational",
            "summary": "DNS lokal menunjukkan IP internal berbeda dari publik (split-horizon, terverifikasi bukan leak)",
            "evidence": f"Local-only private IPs: {', '.join(local_only_private)} (tidak muncul di resolusi publik 8.8.8.8)",
            "recommendation": "Tidak ada aksi diperlukan — ini perilaku split-horizon DNS normal saat scan dijalankan dari jaringan internal.",
            **_explain("dns_split_horizon_info"),
        })

    public_txt = views.get("public_8.8.8.8", {}).get("TXT", {}).get("values", [])
    spf = next((t for t in public_txt if t.lower().startswith("v=spf1")), None)
    if not spf:
        findings.append({
            "category": "Email Security",
            "severity": "Medium",
            "summary": "Tidak ditemukan SPF record",
            "evidence": "Tidak ada TXT record dengan prefix v=spf1 pada resolusi publik",
            "recommendation": "Publikasikan SPF record yang mencakup seluruh mail sender resmi, diakhiri -all setelah divalidasi.",
            **_explain("spf_missing"),
        })
    elif spf.strip().endswith("~all"):
        findings.append({
            "category": "Email Security",
            "severity": "Low",
            "summary": "SPF record menggunakan soft-fail (~all)",
            "evidence": spf,
            "recommendation": "Ubah ke hard-fail (-all) setelah memastikan semua legitimate sender terdaftar.",
            **_explain("spf_softfail"),
        })
    elif not spf.strip().endswith("-all"):
        findings.append({
            "category": "Email Security",
            "severity": "Low",
            "summary": "SPF record tidak diakhiri dengan qualifier tegas (-all)",
            "evidence": spf,
            "recommendation": "Gunakan -all (hard fail) untuk enforcement penuh.",
            **_explain("spf_no_strict"),
        })

    dmarc_values = views.get("public_8.8.8.8", {}).get("DMARC", {}).get("values", [])
    dmarc = next((t for t in dmarc_values if t.lower().startswith("v=dmarc1")), None)
    if not dmarc:
        findings.append({
            "category": "Email Security",
            "severity": "Medium",
            "summary": "Tidak ditemukan DMARC record",
            "evidence": "_dmarc TXT tidak ada / NXDOMAIN pada resolusi publik",
            "recommendation": "Publikasikan DMARC record, mulai dari p=none untuk monitoring lalu naikkan ke quarantine/reject.",
            **_explain("dmarc_missing"),
        })
    elif "p=none" in dmarc.lower():
        findings.append({
            "category": "Email Security",
            "severity": "Medium",
            "summary": "DMARC policy diset p=none (monitor-only, tidak enforce)",
            "evidence": dmarc,
            "recommendation": "Setelah cukup data monitoring (RUA reports), naikkan policy ke p=quarantine lalu p=reject.",
            **_explain("dmarc_p_none"),
        })
    elif "p=quarantine" in dmarc.lower():
        findings.append({
            "category": "Email Security",
            "severity": "Low",
            "summary": "DMARC policy p=quarantine (belum full enforcement)",
            "evidence": dmarc,
            "recommendation": "Pertimbangkan naik ke p=reject setelah memastikan tidak ada false positive.",
            **_explain("dmarc_p_quarantine"),
        })

    return findings


def check_security_headers(base_url, paths, log, session=None):
    client = session or requests
    log(f"Header check start for {base_url}, paths={paths}")
    results = []
    for p in paths:
        url = base_url.rstrip("/") + p
        entry = {"path": p, "url": url}
        try:
            r = client.get(url, timeout=10, allow_redirects=False,
                            headers={"User-Agent": USER_AGENT})
            entry["status"] = r.status_code
            entry["headers"] = dict(r.headers)
            entry["set_cookie"] = _get_set_cookie_headers(r)
            log(f"  {url} -> {r.status_code}")
        except requests.RequestException as e:
            entry["status"] = None
            entry["error"] = str(e)
            log(f"  {url} -> ERROR {e}")
        results.append(entry)
        time.sleep(0.3)
    return results


def _get_set_cookie_headers(response):
    # requests/urllib3 merge repeated headers into one comma-joined string
    # on dict(r.headers) / r.headers.get(), which corrupts multiple
    # Set-Cookie values (cookie attributes also contain commas, e.g. in
    # Expires=Wed, 21...). getlist() on the raw urllib3 HTTPHeaderDict keeps
    # each Set-Cookie header intact and separate.
    try:
        values = response.raw.headers.getlist("Set-Cookie")
        if values:
            return values
    except AttributeError:
        pass
    single = response.headers.get("Set-Cookie")
    return [single] if single else []


SESSION_COOKIE_HINTS = ("sess", "sid", "token", "auth", "jwt", "login", "csrf", "remember")


def _parse_set_cookie(cookie_str):
    parts = [p.strip() for p in cookie_str.split(";") if p.strip()]
    if not parts:
        return None
    name = parts[0].split("=", 1)[0].strip()
    attrs = {"secure": False, "httponly": False, "samesite": None, "max_age": None, "expires": None}
    for part in parts[1:]:
        if "=" in part:
            k, v = part.split("=", 1)
            k = k.strip().lower()
            v = v.strip()
        else:
            k, v = part.strip().lower(), True
        if k == "secure":
            attrs["secure"] = True
        elif k == "httponly":
            attrs["httponly"] = True
        elif k == "samesite":
            attrs["samesite"] = v
        elif k == "max-age":
            try:
                attrs["max_age"] = int(v)
            except ValueError:
                pass
        elif k == "expires":
            attrs["expires"] = v
    return {"name": name, "raw": cookie_str, **attrs}


def collect_cookies(*result_sets):
    cookies = {}
    for results in result_sets:
        for entry in results:
            for raw in entry.get("set_cookie") or []:
                parsed = _parse_set_cookie(raw)
                if parsed and parsed["name"] not in cookies:
                    cookies[parsed["name"]] = parsed
    return [cookies[name] for name in sorted(cookies)]


def analyze_cookie_findings(cookies):
    findings = []
    for c in cookies:
        name = c["name"]
        looks_session = any(h in name.lower() for h in SESSION_COOKIE_HINTS)

        if not c["secure"]:
            findings.append({
                "category": "Cookie Security",
                "severity": "High" if looks_session else "Medium",
                "summary": f"Cookie '{name}' tidak memiliki flag Secure",
                "evidence": c["raw"],
                "recommendation": "Tambahkan atribut Secure pada cookie ini supaya hanya dikirim lewat koneksi HTTPS.",
                **_explain("cookie_missing_secure"),
            })
        if not c["httponly"]:
            findings.append({
                "category": "Cookie Security",
                "severity": "High" if looks_session else "Medium",
                "summary": f"Cookie '{name}' tidak memiliki flag HttpOnly",
                "evidence": c["raw"],
                "recommendation": "Tambahkan atribut HttpOnly supaya cookie ini tidak bisa dibaca lewat JavaScript (document.cookie).",
                **_explain("cookie_missing_httponly"),
            })
        samesite = (c["samesite"] or "").lower()
        if samesite == "none":
            findings.append({
                "category": "Cookie Security",
                "severity": "Medium",
                "summary": f"Cookie '{name}' menggunakan SameSite=None",
                "evidence": c["raw"],
                "recommendation": "Gunakan SameSite=Lax atau Strict kecuali cookie ini memang perlu dikirim cross-site (butuh Secure juga).",
                **_explain("cookie_samesite_none"),
            })
        elif not samesite:
            findings.append({
                "category": "Cookie Security",
                "severity": "Low",
                "summary": f"Cookie '{name}' tidak menyertakan atribut SameSite secara eksplisit",
                "evidence": c["raw"],
                "recommendation": "Set SameSite secara eksplisit (Lax/Strict) daripada mengandalkan default browser.",
                **_explain("cookie_samesite_none"),
            })

        if looks_session:
            lifetime_days = None
            if c["max_age"] is not None:
                lifetime_days = c["max_age"] / 86400
            elif c["expires"]:
                try:
                    exp = datetime.datetime.strptime(c["expires"], "%a, %d %b %Y %H:%M:%S %Z")
                    lifetime_days = (exp - datetime.datetime.utcnow()).days
                except ValueError:
                    pass
            if lifetime_days is not None and lifetime_days > 7:
                findings.append({
                    "category": "Cookie Security",
                    "severity": "Low",
                    "summary": f"Cookie sesi '{name}' berumur panjang (~{int(lifetime_days)} hari) alih-alih session-only",
                    "evidence": c["raw"],
                    "recommendation": "Untuk cookie sesi/auth, pertimbangkan tanpa Max-Age/Expires (session cookie) atau umur pendek, dan pastikan ada enforcement idle-timeout di sisi server.",
                    **_explain("cookie_long_lived"),
                })
    return findings


def analyze_header_findings(header_results):
    findings = []
    if not header_results:
        return findings
    missing_across_all = {}
    disclosed = {}
    checked_paths = [e for e in header_results if e.get("status") is not None]
    for entry in checked_paths:
        headers = entry.get("headers", {})
        for h in SECURITY_HEADERS:
            if not any(k.lower() == h.lower() for k in headers):
                missing_across_all.setdefault(h, []).append(entry["path"])
        for h in INFO_DISCLOSURE_HEADERS:
            match = next((v for k, v in headers.items() if k.lower() == h.lower()), None)
            if match:
                disclosed.setdefault(h, set()).add(match)

    failed_paths = [e["path"] for e in header_results if e.get("status") is None]
    if failed_paths:
        findings.append({
            "category": "HTTP Security Headers",
            "severity": "Informational",
            "summary": f"{len(failed_paths)} dari {len(header_results)} halaman gagal diperiksa (timeout/error), hasil di bawah hanya berdasarkan sisanya",
            "evidence": ", ".join(f"{e['path']} ({e.get('error', 'unknown error')})" for e in header_results if e.get("status") is None),
            "recommendation": "Ulangi scan untuk memastikan halaman ini benar-benar konsisten, atau cek manual apakah server memang lambat/tidak stabil di path tersebut.",
            "apa_itu": "Beberapa halaman tidak sempat merespons dalam batas waktu (10 detik) saat scan dijalankan.",
            "fungsi": "Ini bukan temuan keamanan — cuma transparansi bahwa hasil pengecekan header di bawah ini tidak mencakup 100% halaman yang diminta.",
            "dampak": "Kalau halaman yang gagal ini sebenarnya juga tidak punya header keamanan, temuan Medium terkait bisa jadi under-reported. Disarankan scan ulang untuk konfirmasi.",
        })

    if checked_paths:
        for h, paths in missing_across_all.items():
            if len(paths) == len(checked_paths):
                findings.append({
                    "category": "HTTP Security Headers",
                    "severity": "Medium",
                    "summary": f"Header {h} tidak ditemukan di semua halaman yang berhasil diuji",
                    "evidence": f"Path diuji: {', '.join(paths)}" + (f" (di luar {len(failed_paths)} yang gagal/timeout)" if failed_paths else ""),
                    "recommendation": _header_recommendation(h),
                    **_explain(h),
                })

    for h, values in disclosed.items():
        findings.append({
            "category": "Information Disclosure",
            "severity": "Low",
            "summary": f"Header {h} mengungkap informasi stack/teknologi",
            "evidence": f"{h}: {', '.join(sorted(values))}",
            "recommendation": f"Pertimbangkan menghapus/menyembunyikan header {h} di reverse proxy atau konfigurasi aplikasi.",
            **_explain("info_disclosure"),
        })
    return findings


def _header_recommendation(header):
    mapping = {
        "Strict-Transport-Security": "Tambahkan Strict-Transport-Security: max-age=31536000; includeSubDomains setelah memastikan seluruh subdomain siap HTTPS-only.",
        "Content-Security-Policy": "Tambahkan Content-Security-Policy, mulai dari mode Report-Only untuk observasi sebelum enforcement penuh.",
        "X-Frame-Options": "Tambahkan X-Frame-Options: DENY atau frame-ancestors 'none' di CSP untuk mitigasi clickjacking.",
        "X-Content-Type-Options": "Tambahkan X-Content-Type-Options: nosniff untuk mencegah MIME-sniffing.",
    }
    return mapping.get(header, f"Tambahkan header {header} sesuai best practice OWASP Secure Headers.")


def parse_hsts(header_value):
    attrs = {"max_age": None, "include_subdomains": False, "preload": False}
    if not header_value:
        return attrs
    for part in (p.strip() for p in header_value.split(";") if p.strip()):
        if "=" in part:
            k, v = part.split("=", 1)
            k = k.strip().lower()
            if k == "max-age":
                try:
                    attrs["max_age"] = int(v.strip())
                except ValueError:
                    pass
        else:
            k = part.strip().lower()
            if k == "includesubdomains":
                attrs["include_subdomains"] = True
            elif k == "preload":
                attrs["preload"] = True
    return attrs


def check_hsts(domain, base_url, log):
    log(f"HSTS check for {domain}")
    result = {
        "domain": domain,
        "https_header": None, "https_error": None,
        "http_status": None, "http_location": None,
        "http_redirects_to_https": None, "http_error": None,
        "preload_status": None,
    }
    try:
        r = requests.get(base_url, timeout=10, allow_redirects=False,
                          headers={"User-Agent": USER_AGENT})
        result["https_header"] = r.headers.get("Strict-Transport-Security")
        log(f"  HTTPS Strict-Transport-Security -> {result['https_header']}")
    except requests.RequestException as e:
        result["https_error"] = str(e)
        log(f"  HTTPS fetch failed: {e}")

    # HSTS only protects a browser that has already visited over HTTPS once;
    # a plain http:// entry point that doesn't redirect leaves every "first
    # contact" visit exposed to SSL-stripping regardless of the header above.
    try:
        r2 = requests.get(f"http://{domain}/", timeout=10, allow_redirects=False,
                           headers={"User-Agent": USER_AGENT})
        result["http_status"] = r2.status_code
        location = r2.headers.get("Location", "")
        result["http_location"] = location
        result["http_redirects_to_https"] = (
            r2.status_code in (301, 302, 307, 308) and location.lower().startswith("https://")
        )
        log(f"  HTTP:// -> {r2.status_code} Location={location or '-'}")
    except requests.RequestException as e:
        result["http_error"] = str(e)
        log(f"  HTTP:// fetch failed: {e}")

    try:
        pr = requests.get("https://hstspreload.org/api/v2/status", params={"domain": domain},
                           timeout=10, headers={"User-Agent": USER_AGENT})
        if pr.status_code == 200:
            result["preload_status"] = pr.json().get("status")
            log(f"  hstspreload.org status -> {result['preload_status']}")
    except (requests.RequestException, ValueError) as e:
        log(f"  hstspreload.org lookup failed/skipped: {e}")

    return result


def analyze_hsts_findings(hsts_result):
    findings = []
    header = hsts_result.get("https_header")

    if not header:
        findings.append({
            "category": "HTTP Security Headers",
            "severity": "Medium" if hsts_result.get("http_redirects_to_https") else "High",
            "summary": "Header Strict-Transport-Security (HSTS) tidak ditemukan",
            "evidence": "Tidak ada header Strict-Transport-Security pada respons HTTPS homepage"
                         + ("" if hsts_result.get("http_redirects_to_https")
                            else "; HTTP juga tidak redirect ke HTTPS"),
            "recommendation": _header_recommendation("Strict-Transport-Security"),
            **_explain("Strict-Transport-Security"),
        })
    else:
        attrs = parse_hsts(header)
        if attrs["max_age"] == 0:
            findings.append({
                "category": "HTTP Security Headers",
                "severity": "High",
                "summary": "HSTS dinonaktifkan secara eksplisit (max-age=0)",
                "evidence": f"Strict-Transport-Security: {header}",
                "recommendation": "Hapus max-age=0 dan set max-age ke minimal 15552000 (180 hari), idealnya 31536000 (1 tahun), kecuali memang sedang sengaja mencabut HSTS.",
                **_explain("hsts_disabled"),
            })
        elif attrs["max_age"] is not None and attrs["max_age"] < 15552000:
            findings.append({
                "category": "HTTP Security Headers",
                "severity": "Low",
                "summary": f"HSTS max-age terlalu pendek ({attrs['max_age']} detik, ~{attrs['max_age'] // 86400} hari)",
                "evidence": f"Strict-Transport-Security: {header}",
                "recommendation": "Naikkan max-age ke minimal 15552000 (180 hari), idealnya 31536000 (1 tahun) untuk eligible HSTS preload.",
                **_explain("hsts_short_maxage"),
            })

        if not attrs["include_subdomains"]:
            findings.append({
                "category": "HTTP Security Headers",
                "severity": "Low",
                "summary": "HSTS tidak menyertakan includeSubDomains",
                "evidence": f"Strict-Transport-Security: {header}",
                "recommendation": "Tambahkan includeSubDomains setelah memastikan seluruh subdomain sudah siap HTTPS-only.",
                **_explain("hsts_missing_subdomains"),
            })

    if hsts_result.get("http_status") is not None and not hsts_result.get("http_redirects_to_https"):
        findings.append({
            "category": "HTTP Security Headers",
            "severity": "Medium",
            "summary": "HTTP (port 80) tidak redirect ke HTTPS",
            "evidence": f"http://{hsts_result['domain']}/ -> {hsts_result['http_status']}"
                         + (f" Location: {hsts_result['http_location']}" if hsts_result.get("http_location") else " (tanpa Location redirect)"),
            "recommendation": "Konfigurasikan HTTP (port 80) untuk selalu redirect 301 ke https:// pada semua path.",
            **_explain("hsts_http_no_redirect"),
        })

    preload = hsts_result.get("preload_status")
    if preload and preload not in ("unknown",):
        findings.append({
            "category": "HTTP Security Headers",
            "severity": "Informational",
            "summary": f"Status HSTS preload (hstspreload.org): {preload}",
            "evidence": f"hstspreload.org status: {preload}",
            "recommendation": "Tidak ada aksi wajib — informasi status submission ke Chrome HSTS preload list."
                               if preload == "preloaded" else
                               "Pertimbangkan submit domain ke hstspreload.org setelah HSTS stabil dengan includeSubDomains + preload directive.",
            "apa_itu": "HSTS preload list adalah daftar domain yang di-hardcode di browser (Chrome, Firefox, dll) untuk selalu diakses HTTPS, bahkan sebelum pernah dikunjungi sama sekali.",
            "fungsi": "Menghilangkan total risiko 'first contact' HTTP, karena browser sudah tahu domain ini HTTPS-only sejak awal, tanpa perlu redirect/HSTS header dulu.",
            "dampak": "Kalau belum masuk preload list, user yang mengetik domain tanpa https:// tetap melewati request HTTP pertama yang berpotensi disadap sebelum redirect/HSTS berlaku.",
        })

    return findings


def _fetch_path_signature(base_url, path, log, session=None):
    client = session or requests
    url = base_url.rstrip("/") + path
    entry = {"path": path, "url": url}
    body_hash = None
    try:
        r = client.get(url, timeout=10, allow_redirects=False,
                        headers={"User-Agent": USER_AGENT}, stream=True)
        entry["status"] = r.status_code
        entry["content_type"] = r.headers.get("Content-Type", "")
        entry["content_length"] = r.headers.get("Content-Length", "")
        entry["set_cookie"] = _get_set_cookie_headers(r)
        if r.status_code == 200:
            snippet = next(r.iter_content(4096), b"")
            entry["signatures"] = classify_content(snippet.decode("utf-8", errors="ignore"))
            body_hash = hashlib.sha256(snippet).hexdigest()
        r.close()
        log(f"  {url} -> {r.status_code}" + (f" signatures={entry['signatures']}" if entry.get("signatures") else ""))
    except requests.RequestException as e:
        entry["status"] = None
        entry["error"] = str(e)
        log(f"  {url} -> ERROR {e}")
    entry["_body_hash"] = body_hash
    return entry


def check_sensitive_paths(base_url, paths, log, session=None):
    log(f"Sensitive path enumeration start for {base_url}")

    # Baseline against a path that is guaranteed not to exist: some
    # servers/CDNs/WAFs answer every unmatched path with HTTP 200 and a
    # generic "not found"/catch-all page (soft-404) instead of a real
    # 404/403. Without this baseline, every path below that happens to hit
    # that same fallback page looks indistinguishable from a genuine,
    # individually-served 200 OK and gets reported as "exposed".
    probe_path = f"/__ciwatch_probe_{uuid.uuid4().hex[:16]}"
    baseline = _fetch_path_signature(base_url, probe_path, log, session=session)
    log(f"  soft-404 baseline (known-nonexistent path {probe_path}) -> "
        f"status={baseline.get('status')} len={baseline.get('content_length')}")
    time.sleep(0.3)

    results = []
    for p in paths:
        entry = _fetch_path_signature(base_url, p, log, session=session)
        entry["likely_soft_404"] = bool(
            entry.get("status") == 200
            and baseline.get("status") == 200
            and entry.get("_body_hash") is not None
            and entry.get("_body_hash") == baseline.get("_body_hash")
        )
        entry.pop("_body_hash", None)
        results.append(entry)
        time.sleep(0.3)

    baseline.pop("_body_hash", None)
    return results, baseline


def check_source_maps(base_url, log):
    log(f"Source map discovery for {base_url}")
    try:
        r = requests.get(base_url, timeout=10, headers={"User-Agent": USER_AGENT})
        # sorted(): set() dedupes but iterates in hash order, which is
        # randomized per-process (PYTHONHASHSEED) — without sorting, the
        # "first 15" truncation below would pick a different, inconsistent
        # subset of JS files across app restarts/scans.
        js_files = sorted(set(re.findall(r'src="([^"]+\.js)"', r.text)))
    except requests.RequestException as e:
        log(f"  homepage fetch failed: {e}")
        return []
    exposed = []
    for js in js_files[:15]:
        js_url = js if js.startswith("http") else base_url.rstrip("/") + ("/" + js.lstrip("/"))
        map_url = js_url + ".map"
        try:
            r = requests.get(map_url, timeout=8, headers={"User-Agent": USER_AGENT}, allow_redirects=False)
            if r.status_code == 200 and r.text.strip().startswith("{") and '"sources"' in r.text[:500]:
                exposed.append(map_url)
                log(f"  EXPOSED: {map_url}")
        except requests.RequestException:
            pass
        time.sleep(0.2)
    log(f"  checked {len(js_files)} JS files, {len(exposed)} source map(s) exposed")
    return exposed


def analyze_sensitive_path_findings(path_results, source_maps=None):
    findings = []
    exposed = [e for e in path_results if e.get("status") == 200 and not e.get("likely_soft_404")]
    soft_404_paths = [e["path"] for e in path_results if e.get("likely_soft_404")]
    for e in exposed:
        signatures = e.get("signatures", [])
        evidence = f"{e['url']} -> 200 (Content-Type: {e.get('content_type', '-')}, Content-Length: {e.get('content_length', '-')})"
        if "secrets" in signatures:
            findings.append({
                "category": "Sensitive Path Exposure",
                "severity": "Critical",
                "summary": f"Kredensial/rahasia terdeteksi di path publik: {e['path']}",
                "evidence": evidence,
                "recommendation": "Segera cabut/rotasi kredensial yang bocor, lalu blokir akses publik ke path ini atau hapus dari webroot.",
                **_explain("sensitive_path_secrets"),
            })
        elif "source_code" in signatures:
            findings.append({
                "category": "Sensitive Path Exposure",
                "severity": "High",
                "summary": f"Source code terekspos di path publik: {e['path']}",
                "evidence": evidence,
                "recommendation": "Blokir akses publik ke path ini (403) atau hapus dari webroot. Audit apakah ada kredensial/logika bisnis sensitif di dalamnya.",
                **_explain("sensitive_path_source_code"),
            })
        elif "directory_listing" in signatures:
            findings.append({
                "category": "Sensitive Path Exposure",
                "severity": "Medium",
                "summary": f"Directory listing aktif di path publik: {e['path']}",
                "evidence": evidence,
                "recommendation": "Nonaktifkan directory listing/autoindex di web server (nginx: autoindex off;) untuk direktori ini.",
                **_explain("directory_listing"),
            })
        elif "error_trace" in signatures:
            findings.append({
                "category": "Sensitive Path Exposure",
                "severity": "Medium",
                "summary": f"Stack trace/error verbose terekspos di path publik: {e['path']}",
                "evidence": evidence,
                "recommendation": "Matikan debug/verbose error mode di environment produksi, tampilkan halaman error generik ke publik.",
                **_explain("error_trace_exposed"),
            })
        else:
            findings.append({
                "category": "Sensitive Path Exposure",
                "severity": "High",
                "summary": f"Path berpotensi sensitif dapat diakses (HTTP 200): {e['path']}",
                "evidence": evidence,
                "recommendation": "Segera verifikasi manual isi path ini. Jika benar file/direktori sensitif, blokir akses publik (403) atau hapus dari webroot.",
                **_explain("sensitive_path_exposed"),
            })

    if soft_404_paths:
        findings.append({
            "category": "Sensitive Path Exposure",
            "severity": "Informational",
            "summary": f"{len(soft_404_paths)} path mengembalikan HTTP 200 tapi terindikasi soft-404 (kemungkinan BUKAN exposure nyata)",
            "evidence": f"Body respons path-path ini identik byte-per-byte dengan respons path acak yang sengaja dibuat tidak ada (baseline probe): "
                         + ", ".join(soft_404_paths[:20]) + (" ..." if len(soft_404_paths) > 20 else ""),
            "recommendation": "Jangan anggap path-path ini sebagai temuan valid tanpa verifikasi manual terpisah (akses langsung/cek di server). "
                               "Perbaiki juga server/WAF/CDN agar mengembalikan status 404/403 yang benar untuk path tak dikenal, bukan 200 dengan halaman generik — "
                               "soft-404 membuat scanning berbasis path (termasuk oleh tool ini) tidak reliable dan bisa menyembunyikan temuan asli di antara noise.",
            **_explain("soft_404"),
        })

    if source_maps:
        findings.append({
            "category": "Sensitive Path Exposure",
            "severity": "High",
            "summary": f"{len(source_maps)} file JavaScript source map (.map) dapat diakses publik",
            "evidence": ", ".join(source_maps[:10]) + (" ..." if len(source_maps) > 10 else ""),
            "recommendation": "Nonaktifkan generate/deploy source map ke production (di Next.js: productionBrowserSourceMaps: false), atau blokir akses publik ke file .map.",
            **_explain("sourcemap_exposed"),
        })

    error_statuses = [e for e in path_results if e.get("status") and e["status"] >= 500]
    if error_statuses:
        findings.append({
            "category": "Sensitive Path Exposure",
            "severity": "Informational",
            "summary": f"{len(error_statuses)} path mengembalikan HTTP 5xx alih-alih 403/404",
            "evidence": ", ".join(f"{e['path']} ({e['status']})" for e in error_statuses),
            "recommendation": "Verifikasi dengan tim infra apakah ini WAF/anti-automation control atau instabilitas backend. Pastikan response error tidak membocorkan stack trace.",
            **_explain("error_5xx_pattern"),
        })
    return findings


def check_tls(hostname, port=443, log=None):
    if log:
        log(f"TLS check for {hostname}:{port}")
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                cipher_name, protocol, bits = ssock.cipher()
                tls_version = ssock.version()
        not_after = datetime.datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
        not_before = datetime.datetime.strptime(cert["notBefore"], "%b %d %H:%M:%S %Y %Z")
        subject = dict(x[0] for x in cert.get("subject", []))
        issuer = dict(x[0] for x in cert.get("issuer", []))
        days_left = (not_after - datetime.datetime.utcnow()).days
        result = {
            "tls_version": tls_version,
            "cipher": cipher_name,
            "cipher_bits": bits,
            "subject": subject.get("commonName", "-"),
            "issuer": issuer.get("commonName", "-"),
            "not_before": not_before.isoformat(),
            "not_after": not_after.isoformat(),
            "days_left": days_left,
            "error": None,
        }
        if log:
            log(f"  TLS {tls_version}, cipher {cipher_name}, expires in {days_left} days")
        return result
    except Exception as e:
        if log:
            log(f"  TLS check ERROR: {e}")
        return {"error": str(e)}


def analyze_tls_findings(tls_result):
    findings = []
    if tls_result.get("error"):
        findings.append({
            "category": "TLS",
            "severity": "Informational",
            "summary": "TLS handshake gagal / tidak dapat diverifikasi",
            "evidence": tls_result["error"],
            "recommendation": "Verifikasi manual konektivitas HTTPS ke host target.",
        })
        return findings

    version = tls_result.get("tls_version", "")
    if version in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
        findings.append({
            "category": "TLS",
            "severity": "Critical",
            "summary": f"Protokol TLS lawas terdeteksi: {version}",
            "evidence": f"Negotiated protocol: {version}",
            "recommendation": "Nonaktifkan TLS 1.0/1.1/SSLv3, minimal enforce TLS 1.2, idealnya TLS 1.3.",
            **_explain("tls_legacy"),
        })
    elif version == "TLSv1.2":
        findings.append({
            "category": "TLS",
            "severity": "Low",
            "summary": "Server masih menegosiasikan TLS 1.2 (bukan yang terbaru)",
            "evidence": f"Negotiated protocol: {version}",
            "recommendation": "Pertimbangkan upgrade ke TLS 1.3 jika kompatibilitas klien memungkinkan.",
            **_explain("tls_1_2"),
        })

    days_left = tls_result.get("days_left")
    if days_left is not None and days_left < 30:
        findings.append({
            "category": "TLS",
            "severity": "High" if days_left < 7 else "Medium",
            "summary": f"Sertifikat TLS akan expired dalam {days_left} hari",
            "evidence": f"Valid until: {tls_result.get('not_after')}",
            "recommendation": "Segera perpanjang/renew sertifikat sebelum expired untuk menghindari downtime/browser warning.",
            **_explain("cert_expiring"),
        })
    return findings


def crtsh_lookup(domain, log):
    log(f"crt.sh lookup for {domain}")
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        r = requests.get(url, timeout=20, headers={"User-Agent": USER_AGENT})
        r.raise_for_status()
        data = r.json()
        names = set()
        for entry in data:
            for n in entry.get("name_value", "").split("\n"):
                n = n.strip().lower()
                if n:
                    names.add(n)
        log(f"  found {len(names)} unique names")
        return sorted(names), None
    except Exception as e:
        log(f"  crt.sh ERROR: {e}")
        return [], str(e)


def check_robots_sitemap(base_url, log):
    result = {}
    for name in ["robots.txt", "sitemap.xml"]:
        url = base_url.rstrip("/") + "/" + name
        try:
            r = requests.get(url, timeout=10, headers={"User-Agent": USER_AGENT})
            result[name] = {"status": r.status_code, "body": r.text[:2000] if r.status_code == 200 else ""}
            log(f"{name} -> {r.status_code}")
        except requests.RequestException as e:
            result[name] = {"status": None, "error": str(e)}
            log(f"{name} -> ERROR {e}")
    return result


# Common post-login-only paths worth probing once we have an authenticated
# session — distinct from DEFAULT_SENSITIVE_PATHS, which targets
# misconfiguration on the public/unauthenticated surface.
DEFAULT_AUTHENTICATED_PROBE_PATHS = [
    "/dashboard", "/profile", "/account", "/account/settings", "/settings",
    "/api/me", "/api/user", "/api/profile", "/api/account",
]


def attempt_login(base_url, login_path, user_field, pass_field, username, password, log):
    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT})
    login_url = base_url.rstrip("/") + "/" + login_path.lstrip("/")
    result = {
        "login_url": login_url, "status": None,
        "success_guess": False, "note": None,
        "session_cookie_names": [],
    }
    try:
        # Fetch the login page first: some apps issue a pre-auth session/CSRF
        # cookie here that the POST below depends on, and this captures the
        # cookie baseline so we can tell which cookies are new post-login.
        session.get(login_url, timeout=10, allow_redirects=True)
        pre_cookie_names = set(session.cookies.get_dict().keys())

        resp = session.post(
            login_url,
            data={user_field: username, pass_field: password},
            timeout=10, allow_redirects=True,
        )
        result["status"] = resp.status_code
        post_cookie_names = set(session.cookies.get_dict().keys())
        new_cookies = post_cookie_names - pre_cookie_names
        result["session_cookie_names"] = sorted(post_cookie_names)

        failure_keywords = ("invalid", "incorrect", "salah", "gagal login", "login failed", "wrong password")
        looks_failed = bool(resp.text) and any(kw in resp.text.lower() for kw in failure_keywords)

        result["success_guess"] = bool(new_cookies) and not looks_failed
        result["note"] = (
            f"Cookie session baru terdeteksi setelah POST login (final URL: {resp.url})."
            if result["success_guess"] else
            "Tidak yakin login berhasil — tidak ada cookie baru setelah POST, atau halaman mengandung kata kunci gagal login. "
            "Periksa manual nama field username/password dan path login-nya."
        )
        # Never log credential values — only outcome metadata.
        log(f"  Login POST {login_url} -> {resp.status_code}, final URL {resp.url}, "
            f"cookie baru: {sorted(new_cookies)}, guess success={result['success_guess']}")
    except requests.RequestException as e:
        result["note"] = f"Login request error: {e}"
        log(f"  Login ERROR: {e}")
    return session, result


def run_full_scan(domain, header_paths, sensitive_paths, log, login_config=None):
    base_url = f"https://{domain}"
    findings = []

    dns_views = run_dns_recon(domain, log)
    findings += analyze_dns_findings(dns_views)

    robots = check_robots_sitemap(base_url, log)

    header_results = check_security_headers(base_url, header_paths, log)
    findings += analyze_header_findings(header_results)

    hsts_result = check_hsts(domain, base_url, log)
    findings += analyze_hsts_findings(hsts_result)

    sensitive_results, soft_404_baseline = check_sensitive_paths(base_url, sensitive_paths, log)
    source_maps = check_source_maps(base_url, log)
    findings += analyze_sensitive_path_findings(sensitive_results, source_maps)

    auth_login_result = None
    auth_header_results = None
    auth_sensitive_results = None
    auth_soft_404_baseline = None
    if login_config and login_config.get("login_path") and login_config.get("username") and login_config.get("password"):
        log("Authenticated scan: attempting login")
        auth_session, auth_login_result = attempt_login(
            base_url,
            login_config["login_path"],
            login_config.get("user_field") or "username",
            login_config.get("pass_field") or "password",
            login_config["username"],
            login_config["password"],
            log,
        )
        if auth_login_result.get("success_guess"):
            log("Authenticated scan: re-checking security headers with session")
            auth_header_results = check_security_headers(base_url, header_paths, log, session=auth_session)
            for f in analyze_header_findings(auth_header_results):
                f["category"] = f["category"] + " (Authenticated)"
                findings.append(f)

            log("Authenticated scan: probing post-login-only paths with session")
            auth_sensitive_results, auth_soft_404_baseline = check_sensitive_paths(
                base_url, DEFAULT_AUTHENTICATED_PROBE_PATHS, log, session=auth_session
            )
            for f in analyze_sensitive_path_findings(auth_sensitive_results):
                f["category"] = f["category"] + " (Authenticated)"
                findings.append(f)
        else:
            findings.append({
                "category": "Authenticated Scan",
                "severity": "Informational",
                "summary": "Login dengan kredensial yang diberikan tidak bisa dipastikan berhasil",
                "evidence": auth_login_result.get("note", "-"),
                "recommendation": "Periksa manual path login, nama field username/password, dan kredensialnya. Authenticated scan dilewati untuk run ini.",
                "apa_itu": "CI-Watch mencoba login otomatis sebelum menjalankan authenticated scan, tapi tidak yakin login-nya berhasil berdasarkan heuristik (cookie session baru muncul + tidak ada kata kunci gagal login di respons).",
                "fungsi": "Validasi ini mencegah authenticated scan berjalan di atas asumsi yang salah (dikira sudah login padahal sebenarnya masih anonymous).",
                "dampak": "Kalau temuan ini muncul, bagian authenticated scan (cek header/path setelah login) tidak dijalankan sama sekali untuk scan ini — hasil scan lainnya tetap valid seperti biasa (black-box/anonymous).",
            })
    elif login_config and (login_config.get("username") or login_config.get("password")):
        log("Authenticated scan: dilewati, login_path/username/password belum lengkap diisi")

    cookie_sources = [header_results, sensitive_results]
    if auth_header_results:
        cookie_sources.append(auth_header_results)
    if auth_sensitive_results:
        cookie_sources.append(auth_sensitive_results)
    cookies = collect_cookies(*cookie_sources)
    findings += analyze_cookie_findings(cookies)
    log(f"Cookie check: {len(cookies)} unique cookie(s) observed")

    tls_result = check_tls(domain, log=log)
    findings += analyze_tls_findings(tls_result)

    subdomains, crtsh_error = crtsh_lookup(domain, log)
    if subdomains:
        findings.append({
            "category": "Attack Surface",
            "severity": "Medium" if len(subdomains) > 3 else "Low",
            "summary": f"{len(subdomains)} subdomain teridentifikasi via Certificate Transparency log",
            "evidence": ", ".join(subdomains[:20]) + (" ..." if len(subdomains) > 20 else ""),
            "recommendation": "Review daftar subdomain, pastikan tidak ada yang unnecessarily internet-facing (khususnya panel admin/hosting). Jadikan scope VA lanjutan untuk subdomain yang menangani data sensitif.",
            **_explain("subdomain_surface"),
        })

    severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Informational": 4}
    findings.sort(key=lambda f: severity_order.get(f["severity"], 5))

    return {
        "domain": domain,
        "base_url": base_url,
        "scanned_at": datetime.datetime.utcnow().isoformat() + "Z",
        "dns_views": dns_views,
        "robots": robots,
        "header_results": header_results,
        "hsts_result": hsts_result,
        "sensitive_results": sensitive_results,
        "soft_404_baseline": soft_404_baseline,
        "login_result": auth_login_result,
        "authenticated_header_results": auth_header_results,
        "authenticated_sensitive_results": auth_sensitive_results,
        "authenticated_soft_404_baseline": auth_soft_404_baseline,
        "cookies": cookies,
        "source_maps": source_maps,
        "tls_result": tls_result,
        "subdomains": subdomains,
        "crtsh_error": crtsh_error,
        "findings": findings,
    }
