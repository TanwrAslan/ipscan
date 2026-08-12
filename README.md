# ipscan — hızlı ve güvenli TCP port tarayıcı

Verdiğiniz IP'leri, verdiğiniz portlarda tarar ve her `IP:port` için
**açık / kapalı / filtreli** sonucunu döndürür. Komut satırı ve yerel web
arayüzü olmak üzere iki kullanım biçimi vardır.

* **Bağımlılık yok** — yalnızca Python 3.10+ standart kütüphanesi.
* **Root gerekmez** — ham (SYN) paket değil, normal TCP connect denemesi.
* **Hızlı** — asyncio; loopback'te ~30.000 prob/sn, bir `/24` ağı × 3 port
  1 saniyenin altında.

---

## Kurulum (başka bir cihazda)

Tek gereksinim **Python 3.10 veya üstü**. Kurulacak paket, derlenecek bir şey
yok; depoyu indirip çalıştırmak yeterli.

```bash
git clone https://github.com/TanwrAslan/ipscan.git
cd ipscan
python3 -m ipscan --version
```

Git yoksa: GitHub sayfasında **Code → Download ZIP**, arşivi açın, klasörün
içine girip aynı komutu çalıştırın.

| Sistem | Notlar |
|---|---|
| Linux | Kutudan çıktığı gibi çalışır (`python3`) |
| macOS | Aynı; Python yoksa `brew install python` |
| Windows | Komutlarda `python3` yerine `python`, `./ipscan-run` yerine `python -m ipscan`. Eş zamanlılık otomatik olarak daha temkinli seçilir |

Doğrulama: `python3 -m unittest discover -s tests -t .` → 71 test geçmeli.

## Hızlı başlangıç

```bash
cd ipscan     # depo klasörü

# tek IP, sık kullanılan 100 port
python3 -m ipscan 192.168.1.1 -p top100

# birden çok hedef ve port aralığı
python3 -m ipscan 192.168.1.0/24 10.0.0.5 -p 22,80,443,8000-8100

# web arayüzü (tarayıcı otomatik açılır)
python3 -m ipscan web
```

Kolaylık için `./ipscan-run` betiği de vardır: `./ipscan-run 10.0.0.1 -p 22,80`

---

## Hedef ve port biçimleri

| Hedef | Anlamı |
|---|---|
| `192.168.1.10` | tek IP (IPv4 veya IPv6) |
| `192.168.1.0/24` | CIDR (ağ ve broadcast adresleri hariç tutulur) |
| `10.0.0.10-40` | son oktet aralığı |
| `10.0.0.250-10.0.1.20` | tam IP aralığı |
| `sunucu.local` | alan adı — yalnızca `--resolve` verilirse |
| `-f hedefler.txt` | dosyadan oku (satır/virgül ayrılmış, `#` yorum) |

| Port | Anlamı |
|---|---|
| `22,80,443` | liste |
| `1-1024`, `8000-`, `-1024` | aralık |
| `top100` | en sık kullanılan 116 port (varsayılan) |
| `web` / `db` / `remote` | hazır servis setleri |
| `all` veya `-` | 1-65535 |

## Sonuç durumları

| Durum | Anlamı |
|---|---|
| **açık** | TCP el sıkışması tamamlandı, port dinleniyor |
| kapalı | RST geldi (`connection refused`) — host ayakta, port kapalı |
| filtreli | yanıt yok (güvenlik duvarı sessizce düşürüyor olabilir) |
| erişilemez | ağ/host unreachable (ICMP) |
| hata | yerel hata (ör. kaynak yetersizliği) |

---

## Sık kullanılan seçenekler

```
-p, --ports         portlar (varsayılan: top100)
-t, --timeout       bağlantı zaman aşımı, saniye (varsayılan: 1.0)
-c, --concurrency   eş zamanlı soket (varsayılan: otomatik, güvenli tavana kadar)
-r, --retries       filtreli sonuçlar için ek deneme (varsayılan: 1)
    --rate          saniyedeki azami prob (varsayılan: sınırsız)
    --banner        açık portlarda pasif banner oku (SSH/SMTP/FTP vb.)
    --open-only     yalnızca açık portları raporla
    --json / --csv  rapor dosyası yaz (izinler 0600)
    --ndjson        sonuçları satır satır JSON olarak stdout'a bas
-q, --quiet         ilerleme çubuğunu ve canlı çıktıyı kapat
```

Çıkış kodları: `0` başarılı · `2` hatalı kullanım · `3` kapsam ihlali ·
`130` kullanıcı iptali (Ctrl-C — kısmi sonuçlar yine de yazdırılır).

### Hız ayarı

| Senaryo | Öneri |
|---|---|
| Yerel ağ (LAN) | `-t 0.5 -c 2000` |
| İnternet üzerinden | `-t 2 -c 500 --rate 2000` |
| Tek hostta 65535 port | `-t 1 -c 4000 -r 0` |
| Yavaş/kayıplı hat | `-t 3 -r 2` |

Eş zamanlılık her zaman güvenli tavana (dosya tanımlayıcı bütçesi ve 32768)
kıstırılır; düşürülürse uyarı basılır. Açık bulunan bağlantılar `SO_LINGER=0`
ile kapatılır, böylece sistemde binlerce `TIME_WAIT` soketi birikmez.

---

## Güvenlik

**Kapsam (scope) allowlist.** Yanlışlıkla yetkiniz olmayan bir ağı taramamak
için `scope.txt` dosyası oluşturun:

```
# yalnızca bu ağlar taranabilir
192.168.1.0/24
10.0.0.0/8
127.0.0.1/32
```

Çalışma dizininde `scope.txt` varsa **otomatik olarak zorunlu** hale gelir;
kapsam dışı bir hedef verilirse tarama hiç başlamaz (çıkış kodu 3).

| Mod | Davranış |
|---|---|
| `--scope-mode auto` (varsayılan) | dosya varsa zorunlu, yoksa uyarıp devam eder |
| `--scope-mode strict` | kapsam dosyası zorunlu; yoksa başlamaz |
| `--scope-mode off` | kapsam denetimi kapalı |

Ayrıca hedefler arasında internete açık (global) adres varsa ve kapsam
tanımlı değilse uyarı basılır.

**Diğer önlemler**

* Hiçbir girdi kabuğa (shell) verilmez, `eval` edilmez — komut enjeksiyonu yok.
* Tüm hedef/port girdileri `ipaddress` modülüyle doğrulanır; boyut sınırları
  vardır (≤65536 hedef, ≤5.000.000 toplam prob, ≤256 KB girdi).
* Ham soket / root ayrıcalığı kullanılmaz.
* Banner okuma **pasiftir**: hiçbir veri gönderilmez, yalnızca sunucunun
  kendiliğinden yolladığı ilk 256 bayt okunur.
* Rapor dosyaları `0600` izinleriyle yazılır.

### Web arayüzü güvenliği

`python3 -m ipscan web` yalnızca `127.0.0.1` üzerinde dinler.

* Her çalıştırmada rastgele 256-bit oturum jetonu üretilir; jeton bir kez URL
  ile verilir, sonra `HttpOnly` + `SameSite=Strict` çerezde tutulur.
* `Host` başlığı allowlist'e karşı doğrulanır → **DNS rebinding** engellenir.
* `Sec-Fetch-Site`/`Origin` denetimi ve zorunlu `X-Requested-With` başlığı →
  **CSRF** engellenir.
* Sıkı `Content-Security-Policy`; hiçbir harici kaynak (CDN, font, script)
  yüklenmez, satır içi script yoktur. Arayüz tamamen çevrimdışı çalışır.
* İstek gövdesi 256 KB, eş zamanlı iş sayısı 2, SSE istemcisi 8 ile sınırlıdır;
  işler 1 saat sonra bellekten silinir.
* Ağa açmak (`--host 0.0.0.0`) bilinçli olarak zorlaştırılmıştır:
  `IPSCAN_ALLOW_REMOTE=1` ortam değişkeni olmadan reddedilir. Önerilmez.

---

## Testler

```bash
python3 -m unittest discover -s tests -t .      # tümü (71 test)
python3 -m unittest tests.test_security -v      # yalnızca güvenlik testleri
```

Motor testleri gerçek loopback soketleri kullanır, dışarıya ağ trafiği üretmez.

### Güvenlik testleri (`tests/test_security.py`)

Gerçek bir web sunucusu ayağa kaldırılıp saldırgan gibi istek gönderilir.
Kapsanan saldırılar:

| Saldırı | Beklenen |
|---|---|
| Jetonsuz / yanlış / kırpılmış jeton | 401 |
| Sahte `Host` başlığı (DNS rebinding) | 421 |
| Cross-site fetch, yabancı `Origin` | 401 |
| `X-Requested-With` olmadan POST (form CSRF) | 403 |
| Path traversal (`../etc/passwd`, `%2f` varyantları) | 400/404 |
| Komut enjeksiyonu (`; rm -rf /`, `` `id` ``, `$(reboot)`) | 400 |
| Bozuk port ifadeleri, alan adı (izinsiz) | 400 |
| 256 KB üstü gövde, yalan `Content-Length` | 413 + bağlantı kapanır |
| Uçuk parametreler (`timeout=99999`, `concurrency=1e9`) | kıstırılır |
| Kapsam dışı hedef, IPv4-mapped IPv6 ile atlatma | 403 |
| Sonsuz SSE akışına HEAD (iş parçacığı tüketme) | 405 |
| CSV formül enjeksiyonu (`=cmd\|...` banner'ı) | nötrlenir |
| Rapor dosyası izinleri | 0600 |

### Harici araçlarla tarama (isteğe bağlı)

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install bandit semgrep pip-audit

bandit -r ipscan/ -ll          # Python güvenlik lint'i
semgrep --config=p/python .    # kural tabanlı statik analiz
pip-audit                      # bağımlılık CVE'leri (bu projede bağımlılık yok)
```

Claude Code içinde: `git init && git add -A` sonrası `/security-review`
komutu değişiklikleri inceler.

## Dosya düzeni

```
ipscan/
  targets.py   hedef/port ayrıştırma ve doğrulama
  scope.py     kapsam (allowlist) denetimi
  limits.py    fd bütçesi ve güvenli eş zamanlılık
  engine.py    asyncio TCP connect motoru
  report.py    tablo / JSON / CSV / ndjson çıktı
  cli.py       komut satırı arayüzü
  webapp.py    yerel HTTP sunucusu + SSE
  static/      web arayüzü (html/css/js)
tests/         birim testleri
```

---

**Yasal uyarı:** Bu araç yalnızca sahibi olduğunuz veya taramak için yazılı
izniniz bulunan sistemlerde kullanılmalıdır. İzinsiz port taraması çoğu
ülkede suçtur.
