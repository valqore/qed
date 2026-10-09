# qed — Tasarım Kararları (ADR)

Durum işaretleri: **ÖNERİ** (onay bekliyor) · **KABUL** · **RET** · **ERTELENDİ**
Her karar: bağlam → seçenekler → öneri → sonuçları → açık sorular. Kabul edilenler repoya `docs/adr/NNNN-*.md` olarak girer.

---

## ADR-001 — Atlatma direnci: adaptör sınıfları ve kimlik bilgisi aracılığı
**Durum:** KABUL (4 Ekim 2026) — Broker v1 kapsamında; secret store v1: env + dosya + Vault
**Boşluk:** Review A-1

### Bağlam
Üç adaptör (hook, MCP proxy ayarı, `HTTPS_PROXY`) ajanın kendi ortamında çalışır ve ajan ya da geliştirici tarafından kapatılabilir. Prompt injection ile ele geçirilmiş bir ajan `settings.json`'dan hook'u silebilir. "QED atlatılamaz" cümlesi bu adaptörler için yanlıştır. Gerçek zorlama, ajanın qed olmadan hedefe ulaşamadığı durumdur.

### Seçenekler
| | Yaklaşım | Zorlama gücü | Kurulum maliyeti |
|---|---|---|---|
| A | Sadece adaptörler (hook / proxy ayarı / env) | **Advisory** — iyi niyetli ajanı yönlendirir, kötü niyetliyi durdurmaz | Dakikalar |
| B | A + **Credential Broker**: upstream kimlik bilgileri (DB şifresi, bulut anahtarı, MCP OAuth token'ı) qed'te; ajan hiç görmez, qed her çağrıda kısa ömürlü türetilmiş kimlik bilgisi kullanır | **Enforcing** — qed atlansa bile ajan kimliksizdir, çağrı başarısız | Saatler; secret store entegrasyonu |
| C | B + **ağ seviyesi**: ajan pod'unun tek egress'i qed (NetworkPolicy / güvenlik grubu) | **Enforcing+** — HTTP dahil her çıkış qed'ten | Platform ekibi işi; K8s/VPC gerekir |

### Öneri
**Üç sınıfı da destekle, her adaptörü sınıfıyla etiketle, denetçiye sınıfı yaz.** v1'de B zorunlu bileşen, C dokümante edilmiş referans mimari.

1. Yeni bileşen **`core/broker`**: upstream başına kimlik bilgisi kaydı (`upstreams.yaml`), kaynaklar: env, dosya, Vault, AWS Secrets Manager, Azure Key Vault. MCP proxy ve HTTP proxy, ALLOW aldıktan sonra isteği **broker'dan aldığı kimlik bilgisiyle** upstream'e iletir; ajanın gönderdiği `Authorization` başlığı atılır. Ajan tarafında sadece qed'in delegation token'ı vardır.
2. Her `ActionProposal.context.adapter` alanına **`enforcement: advisory | enforcing`** eklenir. Hook ve SDK her zaman `advisory`; MCP/HTTP proxy, broker devredeyse `enforcing`, değilse `advisory`.
3. `EvidenceRecord` bu alanı taşır; OSCAL ihracatında `advisory` kayıtlar ayrı bir `observation` türüyle işaretlenir. Denetçi "insan onayladı" (güçlü) ile "ajan qed'ten geçti ama geçmeyebilirdi" (zayıf) arasındaki farkı görür.
4. `qed doctor` çıktısında posture özeti: "3 upstream broker'da, 2 upstream advisory (ajan kendi kimliğini taşıyor) — enforcing için şunları taşıyın."
5. Referans mimari dokümanı: K8s NetworkPolicy + egress gateway örneği; "enforcing+" istiyorsan bu.
6. Hook adaptörü için ek savunma (advisory'yi biraz güçlendirir, enforcing yapmaz): Claude Code managed settings (`allowManagedPermissionRulesOnly`) ile hook'un kullanıcı tarafından silinememesi; dokümante edilir, zorlanmaz.

### Sonuçlar
- Kapsam artar: broker v1'e girer (~Faz 2, 1 hafta). Karşılığında "atlatılamaz" cümlesi dürüst hale gelir.
- Satış cümlesi değişir: "ajanlarınıza dokunmuyoruz" doğru kalır; "ajan atlatamaz" sadece broker/egress'te söylenir.
- Ajan hiçbir upstream kimlik bilgisi tutmadığı için **sızıntı yüzeyi küçülür** — bu başlı başına satış argümanı (Supabase MCP ve AgentCore sızıntı vakaları).
- Broker, qed'i kimlik bilgisi tutan bir hedef yapar; kernel'ın kendi güvenliği (ADR-007'de) önem kazanır.

### Açık sorular
- Broker'ın secret store entegrasyonları v1'de kaç tane? Öneri: env + dosya + Vault; AWS/Azure v1.x.
- MCP upstream OAuth akışında (RFC 9728 PRM) qed'in "istemci" olarak kaydı — CIMD olgunlaşana kadar manuel client_id.

---

## ADR-002 — Politika semantiği
**Durum:** KABUL (4 Ekim 2026) — default ALLOW+kayıt; ALLOW kuralı yok; override sadece yumuşatır; kapatma gerekçeli
**Boşluk:** Review A-3

### Bağlam
Kural dili "applies_to + predicate + verdict" olarak tanımlandı ama çakışma, öncelik, varsayılan ve override semantiği yazılmadı. Bunlar `policy/engine.py`'nin ilk 50 satırını ve bütün golden testleri belirler.

### Kararlar (öneri)

**2.1 Varsayılan karar — eşleşen kural yoksa**
| | Seçenek | Lehine | Aleyhine |
|---|---|---|---|
| A | `ALLOW` + `AG-DEF-001 no_rule_matched` kaydı | Benimseme kolay, shadow'dan enforce'a yumuşak geçiş, Valqore'un mevcut davranışı | "Default-deny" güvenlik ilkesine ters görünür |
| B | `BLOCK` | Güvenlik saflığı | İlk gün her şey kırılır; kimse açmaz |
| C | Ortam bazlı: `dev/staging → ALLOW`, `prod → REQUIRE_APPROVAL` | İkisinin ortası | Karmaşıklık, sürpriz |

**Öneri: A, ama `qed.yaml`'da `default_verdict` ile değiştirilebilir ve `prod` için `REQUIRE_APPROVAL` önerilen (dokümante) ayar.** Baseline paketi zaten prod/delete/para/network gibi riskli sınıfları kapsar; "hiç kural eşleşmedi" nadir ve kayıtlı olur. Denetçi için `no_rule_matched` oranı bir metrik: yüksekse politika eksik.

**2.2 Öncelik — birden fazla kural tetiklenince**
Deterministik sıralama, en kısıtlayıcı kazanır: **`BLOCK > REQUIRE_APPROVAL > ALLOW`**. Severity karara etki etmez (sadece raporlama ve `--max-severity` eşiği için). Tetiklenen *tüm* kuralların ID'leri verdict'e yazılır, sadece kazananın değil. Sıra bağımsızlığı golden testle garanti edilir (kuralların yükleme sırası değiştirilince sonuç aynı).

**2.3 ALLOW kuralı var mı?**
**Hayır.** Kurallar sadece kısıtlar (`BLOCK`, `REQUIRE_APPROVAL`) ya da sessizdir. Allowlist semantiği istenirse `applies_to` ile daraltılır ("prod dışında bu kural çalışmaz"). Sebep: ALLOW kuralı + BLOCK kuralı çakışması çözümsüzdür ve politika okumayı imkânsız kılar (firewall kuralı sorunu). İstisna mekanizması `override` ile (2.4).

**2.4 Override semantiği**
Sadece **yumuşatma**, asla sertleştirme yok; alan bazlı:
```yaml
- rule_id: AG-DAT-007
  override:
    verdict: REQUIRE_APPROVAL      # BLOCK → onay (izinli)
    applies_to: { environment: [staging] }   # kapsamı daraltma (izinli)
    # verdict: ALLOW  → lint hatası: kural tamamen kapatılamaz; "disabled: true" + gerekçe ister
```
Bir kuralı kapatmak için `disabled: true` + `reason:` zorunlu; `policy_loaded` kaydına girer, denetçi görür. Sertleştirme için yeni kural yazılır (override değil).

**2.5 Predicate seti (v1, sabit)**
`equals`, `in`, `glob`, `regex`, `gt/gte/lt/lte` (sayısal: blast radius, cost_estimate, budget kalan), `exists`, ve mantık: `any`, `all`, `not`. Hepsi `ActionProposal` alanları ve `hints` üzerinde. Python predicate/plugin **yok** (v2). `param_matches` gibi ham parametre erişimi sadece `params_redacted` üzerinde çalışır — ham veri kernel'a hiç gelmez.

**2.6 Shadow modu kural seviyesinde**
Her kuralda `mode: enforce | shadow` (varsayılan: paket seviyesi ayarı). Shadow kural tetiklenirse verdict'i etkilemez, `would_verdict` alanına yazılır ve kanıt kaydı `mode: shadow` taşır. Bu, Review A-2'nin yarısını kapatır (servis seviyesi shadow ADR-003'te).

**2.7 Bundle hash ve sürüm**
`policy_hash = sha256(canonical_json(sorted rules))`. Her verdict'te. `policy_loaded` kaydı: eski hash → yeni hash, kim yükledi, diff özeti (kaç kural eklendi/değişti/kapatıldı). Lint: aynı `rule_id` iki kez → hata; `override` hedefi yoksa → hata; regex derlenemiyorsa → hata; `disabled` gerekçesiz → hata.

**2.8 Lint ve test komutları**
`qed policy lint` (statik), `qed policy test` (`tests/*.yaml`: proposal + beklenen verdict + beklenen rule_ids), `qed policy explain <proposal.json>` (hangi kurallar neden tetiklendi — operatörün debug aracı).

### Sonuçlar
- Motor küçük kalır (~300 satır) ve tamamen saf.
- Kural yazarı için öğrenme eğrisi: bir sayfa doküman.
- "Neden geçti" sorusu her zaman cevaplanabilir: `no_rule_matched` ya da tetiklenen kural listesi.
- Allowlist isteyen müşteri `applies_to` ile çözer; çözemiyorsa v2'de "exception" kavramı değerlendirilir.

### Açık sorular
- `default_verdict: ALLOW` seçimini CISO alıcısına nasıl anlatırız? Öneri: "default-deny'ı broker'da (ADR-001) yapıyoruz — kimliği olmayan çağrı zaten geçemez; politika katmanı risk sınıflandırır." İki katmanlı savunma argümanı.
- Severity'nin karara etki etmemesi Valqore'dan farklı (`--max-severity`). Geriye uyum gerekmiyor (yeni ürün) ama Valqore kullanıcısı için geçiş notu.

---

## ADR-003 — Çalışma modları: shadow, enforce ve fail davranışı
**Durum:** KABUL (4 Ekim 2026)
**Boşluk:** Review A-2

### Bağlam
Hiçbir platform ekibi ilk gün `fail_closed` ile üretime koymaz. "Ne bloke edecektim" sorusunu cevaplayan gözlem modu olmadan politika kalibre edilemez. `fail_open/closed` çökme davranışıdır, çalışma modu değil; ikisi karıştırılmamalı.

### Karar (öneri)
İki bağımsız eksen, ikisi de adaptör bazında:

**Mod** — kararın uygulanıp uygulanmadığı
| Mod | Davranış | Kanıt |
|---|---|---|
| `shadow` | Her şey geçer; kernel tam değerlendirir; `would_verdict` kaydedilir | `mode: shadow`, zincire girer |
| `enforce` | Verdict uygulanır | `mode: enforce` |

Kural seviyesinde de `mode` var (ADR-002.6); servis `shadow` ise kural `enforce` olsa bile geçer; servis `enforce` iken kural `shadow` olabilir (yeni kural denemesi).

**Fail** — kernel ulaşılamazsa adaptör ne yapar
| Adaptör | Varsayılan | Not |
|---|---|---|
| MCP proxy (broker'lı) | `closed` | Zaten kimlik bilgisi qed'te; açık olması anlamsız |
| HTTP proxy | `closed` | prod; dev profilinde `open` |
| Hook / SDK | `open` + yerel JSONL'e `ungated: true` kaydı | Advisory zaten; kapalı olması geliştiriciyi durdurur, güvenlik katmaz |
| CI komutu | `closed` (exit ≠ 0) | Pipeline durur |

Kernel ulaşılamadığında adaptör yerel bir "açık tutuldu" kaydı yazar; kernel dönünce bu kayıtlar `ungated_window` olarak zincire eklenir (başlangıç/bitiş zamanı, kaç çağrı). Denetçi boşluğu görür; gizlenmez.

**Onboarding yolu (dokümante):** `shadow` 1-2 hafta → `qed report --shadow` ile "şunlar bloke olacaktı" listesi → politika düzeltme → `enforce`. `qed doctor` servis shadow'da 14 günden uzun kalmışsa uyarır.

### Sonuçlar
- Benimseme engeli kalkar; ilk günden üretim trafiğinde çalışır.
- Shadow kayıtları da zincirde olduğu için "şu tarihten beri gözlemliyoruz" denetçiye gösterilebilir.
- Adaptör tarafında küçük bir yerel kuyruk gerekir (hook/SDK için `~/.qed/pending.jsonl`).

---

## ADR-004 — Kanıt zinciri: yazar modeli, şema sürümü, checkpoint
**Durum:** KABUL (4 Ekim 2026) — tek yazar lideri; schema_version 1.0; Ed25519 + key_id
**Boşluk:** Review A-4

### Bağlam
`seq` tek ve monotonik zincir varsayıyor. 2+ replica ve Postgres'te iki yazar çatışır. Ayrıca `EvidenceRecord`'da `schema_version` yok; format ileride spec olacaksa ilk kayıttan itibaren gerekli.

### Seçenekler
| | Model | Artı | Eksi |
|---|---|---|---|
| A | **Tek yazar lideri**: Postgres advisory lock ile bir replica yazar, diğerleri ona iletir (ya da yazma isteğini DB'de sıraya koyar, lider işler) | Basit, `qed-verify` tek zincir doğrular | Lider devrilmesi sırasında kısa yazma duraksaması (ms-sn) |
| B | **Replica başına zincir** + periyodik birleşik checkpoint | Yazma daralması yok | Doğrulama karmaşık, "zincir bütün mü" sorusu çok zincirli cevap ister |
| C | **DB-atanmış seq** (Postgres `SERIAL`/sequence) + `prev_hash` için son kaydı oku-yaz transaction'ı | Lider yok | Yüksek eşzamanlılıkta serialization hataları ve retry |

### Öneri
**A (tek yazar lideri) v1; B v2'de gerekirse.** SQLite modunda zaten tek yazar. Postgres'te `pg_advisory_lock(gate_chain)` tutan replica "chain writer"; diğer replica'lar karar verir (saf fonksiyon, lidersiz), kanıt yazımını `evidence_outbox` tablosuna atar, lider sıralı olarak zincire alır. Karar gecikmesi lidere bağlı değil; yalnız kanıtın zincire girmesi birkaç ms gecikir. Lider düşerse lock serbest kalır, başka replica alır; outbox kaybolmaz.

**Şema kararları:**
- `EvidenceRecord.schema_version: "1.0"` zorunlu, hash girdisine dahil.
- `hash = sha256(schema_version || seq || ts || type || payload_hash || prev_hash)` — alan ayracı `0x1f`, canonical JSON (RFC 8785 JCS) ile payload_hash.
- `key_id` zorunlu; `sig = Ed25519(hash)`.
- İlk kayıt `genesis`: `prev_hash = sha256("gate-genesis:" + instance_id)`.
- `checkpoint` kaydı: her 1.000 kayıt ya da 1 saat (hangisi önce); `merkle_root` son checkpoint'ten bu yana kayıtların kökü; `published_to[]` (ADR'de belirlenen dış yayın hedefleri: S3 object-lock, git tag, e-posta, v1.x'te qed şeffaflık günlüğü).
- `qed-verify` iki mod: `--full` (her imza) ve `--checkpoints` (sadece kökler, hızlı); denetçi ikisini de kullanabilir.
- Kayıt payload'ı asla değiştirilmez; düzeltme = yeni `correction` tipi kayıt, önceki `seq`'e referansla.

### Sonuçlar
- HA'da yazma tek noktada toplanır; p95 hedefi (50 ms) karar için geçerli, kanıt yazımı asenkron.
- Spec'e dönüşebilecek kadar belirli bir format; `docs/evidence-format.md` ilk gün yazılır.

---

## ADR-005 — Kişisel veri ve silme hakkı
**Durum:** KABUL (4 Ekim 2026) — pseudonymization + silinebilir eşleme tablosu
**Boşluk:** Review A-5

### Bağlam
`principal.human_sub` (e-posta/OIDC sub), `approver_sub`, Slack kullanıcı adı kişisel veridir. GDPR/KVKK silme talebi append-only zincirle çelişir. Sonradan eklenemez; şema kararı.

### Seçenekler
| | Yaklaşım | Artı | Eksi |
|---|---|---|---|
| A | **Pseudonymization**: zincirde `sha256(sub + instance_salt)`; `sub ↔ hash` eşlemesi ayrı, silinebilir tabloda | Basit; zincir hiç PII taşımaz; silme = eşleme satırını sil | Hash geri alınamaz ama eşleme tablosu varken "takma ad" sayılır (GDPR'da hâlâ kişisel veri; silinince anonim) |
| B | **Crypto-shredding**: kişi başına anahtarla şifreli `sub`; silme = anahtarı yok et | Zincirde okunabilir (anahtarla) tam kimlik | Anahtar yönetimi karmaşık; anahtar sızarsa her şey açılır |
| C | Düz metin + "meşru menfaat / yasal yükümlülük" dayanağı, silme reddi | Sıfır mühendislik | Avrupa'da regüle müşteri güvenlik incelemesinde takılır |

### Öneri
**A, B'nin bir parçasıyla:** zincirde yalnız `principal_hash`; eşleme tablosu `principals(hash, sub, display_name, created_at, erased_at)`; silme talebi `sub` ve `display_name`'i siler, `erased_at` yazar; zincir dokunulmaz. Denetçi için: silinmiş kişi "principal #a3f9…" olarak görünür, "kimin onayladığı" sorusu "yetkili bir insanın onayladığı" olarak hâlâ kanıtlanabilir (hash değişmedi, SoD kontrolü hash üzerinden). Onay anında Slack'e giden isim eşleme tablosundan okunur, zincire girmez.

Ek kurallar: `params_redacted` içinde e-posta/telefon/IBAN/anahtar desenleri kayıt anında maskelenir (regex seti, test edilir); `intent` metni (ajanın niyeti) serbest metin olduğu için aynı maskelemeden geçer; saklama süresi `qed.yaml`'da (`retention: 7y` DORA için), süre dolunca payload'lar silinir ama `hash` ve `sig` kalır — zincir bütünlüğü bozulmaz, içerik gider.

### Sonuçlar
- Zincir baştan PII'sız; "silme talebi geldi" senaryosu bir SQL satırı.
- Eşleme tablosu yedeklenmeli; kaybolursa denetçi kimlikleri çözemez (zincir yine geçerli).

---

## ADR-006 — Onay bağlamı, kapsamı ve yeniden deneme
**Durum:** KABUL (4 Ekim 2026) — pencereli onay var, varsayılan 15 dk / maks 60; 'forever' yok
**Boşluk:** Review A-6

### Bağlam
Onaylayan karar vermek için bağlam ister (ne, neden, kim); biz ham parametre saklamıyoruz. Onayın kapsamı tanımsızsa aynı kart gece on kez gelir.

### Karar (öneri)

**6.1 Onay bağlamı** — `ApprovalRequest` içinde, kernel oluşturur:
- `summary`: adaptörün ürettiği tek satır ("DROP TABLE orders on db:prod") — adaptör ham parametreyi görür, özeti üretir, kernel özeti maskelemeden geçirir.
- `intent`: ajanın beyan ettiği niyet (varsa; MCP'de `_meta.intent`, hook'ta ajan mesajından, SDK'da parametre).
- `principal`: insan (display_name eşlemeden), ajan zinciri, cihaz.
- `risk`: tetiklenen kural ID'leri + açıklamaları, blast radius skoru, `environment`.
- `history`: aynı ajanın son 24 saatte bu hedefte kaç çağrısı, kaçı bloke.
- `params_redacted`: maskelenmiş parametre (katlanabilir, varsayılan kapalı).
Ham parametre onaylayana **gösterilmez**; adaptörün ürettiği özet yeterli değilse onaylayan "reddet, daha fazla bilgi iste" der ve ajan yeniden, daha açıklayıcı `intent` ile dener.

**6.2 Onay kapsamı** — onaylayan üç seçenek görür:
| Seçenek | Anlamı | Kanıt |
|---|---|---|
| **Approve once** | Sadece bu `proposal_id` | `approval_decided{scope: once}` |
| **Approve for N min** | Aynı `principal_hash` + aynı `action.name` + aynı `target` için N dakika (politika üst sınır koyar, varsayılan 15, maks 60) | `approval_decided{scope: window, until}`; pencere içindeki her çağrı `ALLOW via approval #id` kaydıyla geçer |
| **Deny** | Reddet; opsiyonel gerekçe | `approval_decided{decision: deny}` |
"Approve forever" **yok** — kalıcı istisna politika değişikliğidir (`override`/`disabled`), onay değil; denetçi ikisini ayrı görmeli.

**6.3 Yeniden deneme ve tekilleştirme**
- Aynı `principal + action + target + params_hash` 10 dakika içinde tekrar gelirse yeni kart açılmaz; mevcut `pending` isteğe bağlanır (`proposal.linked_approval`). Ajan "bekleyen onay var, #id" cevabı alır.
- `params_hash` farklıysa yeni istek (ajan parametreyi değiştirmiş; onaylayan farkı görmeli).
- Reddedilen istekle aynı imza 10 dakika içinde gelirse doğrudan BLOCK + `denied_recently` (onaylayanı spam'den korur).

**6.4 Zaman aşımı ve eskalasyon**
- Politika `timeout` (varsayılan 10 dk) → `expired` → BLOCK.
- Opsiyonel `escalate_to`: ilk grup N dakikada cevap vermezse ikinci gruba kart.
- Onaylayan yoksa (grup boş/çevrimdışı) kernel bunu `approval_unreachable` olarak kaydeder — "insan gözetimi vardı ama kimse yoktu" denetçi için önemli.

### Sonuçlar
- On-call deneyimi yaşanabilir olur; Slack kartı tek başına karar verdirir.
- Pencereli onay, "insan gözetimi" kavramını zayıflatır gibi görünebilir; üst sınır politikada ve her pencere kaydı zincirde — denetçi "15 dakikalık pencereler" olduğunu görür ve kabul eder (SRE pratiğinde change window ile aynı).

---

## ADR-007 — Kanıt güven sınıfları ve kernel'ın kendi güvenliği
**Durum:** KABUL (4 Ekim 2026)
**Boşluk:** Review A-7 (+ ADR-001'in getirdiği yeni yüzey)

### 7.1 Kanıt güven sınıfları
Her kayıt `assurance` alanı taşır; OSCAL'da ayrı observation türü:
| Sınıf | Kim üretir | Ne kanıtlar |
|---|---|---|
| `kernel` | Kernel kendisi (proposal, verdict, approval, budget, policy_loaded, key_rotated) | Karar ve onay gerçekten böyle verildi — **güçlü** |
| `broker` | Kernel, upstream'e kendisi ilettiği için (`executed`, `execution_result` broker modunda) | Onaylanan çağrı gerçekten yapıldı ve sonucu bu — **güçlü** |
| `adapter` | Ajanın ortamındaki adaptör bildirir (`executed` advisory modda, hook/SDK) | Adaptör böyle dedi — **zayıf**, spoof edilebilir |
| `self` | Shadow/ungated pencereler, yerel kuyruktan sonradan gelen kayıtlar | Boşluk beyanı |
Denetçi dokümanında açık cümle: "İnsan onayı kanıtı her zaman `kernel` sınıfındadır. Yürütme kanıtı broker kullanımında `broker`, aksi halde `adapter` sınıfındadır." Bu, ADR-001'in `enforcement` alanıyla birebir uyumlu.

### 7.2 Kernel'ın kendi güvenliği (broker ile hedef haline geldi)
- Broker secret'ları bellekte; diske sadece şifreli (KMS/Vault referansı) ya da hiç.
- Kernel API'si mTLS ya da en az OIDC bearer; adaptörler kernel'a kendi kimliğiyle gelir (`adapter_id` + anahtar).
- Admin işlemleri (`policy reload`, `keys rotate`, `upstreams` değişikliği) kendi kapısından geçer: REQUIRE_APPROVAL + farklı admin (SoD) + zincir kaydı. Kernel kendi kurallarına tabi.
- Rate limit: ajan başına proposal/sn; onay spam'i ADR-006.3.
- Kernel binary'si cosign imzalı; `qed doctor` çalışan binary'nin imzasını doğrular.
- Threat model dokümanı (`THREAT_MODEL.md`) ilk release'te: STRIDE tablosu — ajan, geliştirici, iç saldırgan, kernel operatörü, upstream.

---

## ADR-008 — Token akışları: insan ve gözetimsiz ajan
**Durum:** KABUL (4 Ekim 2026) — device flow (insan); client-credentials + imzalı Mandate ZORUNLU (gözetimsiz)
**Boşluk:** Review A-8

### Bağlam
İnsan geliştirici her 30 dakikada Okta'ya login olamaz. Gece çalışan SRE ajanı "kimin adına" çalışıyor? EU AI Act Art. 14 bu soruyu soruyor.

### Karar (öneri)

**8.1 İnsan arkasındaki ajan (attended)**
- `qed login` → OAuth **device authorization flow** (RFC 8628): terminalde kod, tarayıcıda Okta onayı; refresh token `~/.qed/` altında OS keychain'de (macOS Keychain, Linux secret-service), dosyada değil.
- `qed token` → refresh token ile kernel'dan **delegation token** (RFC 8693 exchange): 30 dk ömür, `act: [agent_id]`, bütçe claim'leri, kapsam = kullanıcının grup üyeliğinden türetilen politika (`qed.yaml` → `scopes_by_group`).
- Adaptörler token'ı otomatik yeniler (refresh varken sessiz; refresh dolunca `qed login` ister — günde bir).
- Bütçe token ömrüne bağlı: yeni token = yeni bütçe; politika "günlük toplam" isterse `principal_hash` bazında ikinci sayaç.

**8.2 Gözetimsiz ajan (unattended)**
- Ajanın kendi kimliği: OAuth **client credentials** (IdP'de servis hesabı) ya da K8s **service account token** (projected, audience=qed) ya da SPIFFE SVID (v1.x).
- Tek başına yetmez: **imzalı Mandate** gerekir — bir insanın önceden imzaladığı görev tanımı:
  ```yaml
  mandate:
    id: md_2026_10_sre_nightly
    issued_by: oncall-lead@acme      # insan, OIDC ile imzalar (qed mandate sign)
    for_agent: sre-agent@prod-runner
    purpose: "Payment-api alarmlarına otomatik müdahale"
    allowed: { kinds: [http], targets: ["aws:ec2:*", "aws:rds:describe*"], environments: [prod] }
    budget: { steps: 20, seconds: 600, money_cents: 0 }
    valid: { from: 2026-10-01, until: 2026-12-31 }
    oversight: { approvers: [sre-oncall], require_approval_for: ["blast_radius > 60"] }
  ```
- Delegation token `act: [sre-agent]`, `mandate: md_…`; politika mandate'in `allowed` kümesini **ek kısıt** olarak uygular (mandate dışı = BLOCK, `AG-IDN-006 outside_mandate`).
- Mandate imzası zincire `mandate_issued` kaydı; süresi dolunca ajan token alamaz. Yenileme insan ister — Art. 14'ün "insan gözetimi" cevabı tam burası: insan her çağrıda yok ama görevi tanımlayan, sınırlayan ve periyodik yenileyen insan var.

**8.3 Zincir daralma kuralı (her iki akışta)**
`act` zincirinde her halka: `scopes ⊆ önceki`, `budget ≤ önceki`, `exp ≤ önceki`. Alt-ajan daha fazla alamaz. İhlal `AG-IDN-003`.

### Sonuçlar
- Geliştirici günde bir login; ajan sessiz çalışır.
- Gözetimsiz ajan için "mandate" kavramı ürünün regülasyon hikâyesinin merkezi olur; Google AP2 mandate'leriyle ileride eşlenebilir (ERTELENDİ).
- IdP'ye bağımlılık: device flow her OIDC sağlayıcıda var; client credentials de. Keycloak ile yerel test yeterli.

---

## Kabul edilince plana etkisi (v0.3 için not)
- Yeni bileşen: `core/broker` (ADR-001) → Faz 2'ye +1 hafta.
- Yeni bileşen: `core/mandate` (ADR-008) → Faz 2 içinde, küçük.
- `schemas.py` alanları: `enforcement`, `assurance`, `mode`, `schema_version`, `principal_hash`, `mandate_id`, `linked_approval`, `would_verdict`.
- Yeni dokümanlar ilk release'te: `docs/evidence-format.md`, `THREAT_MODEL.md`, `docs/onboarding-shadow-to-enforce.md`, `docs/assurance-classes.md` (denetçi için).
- Faz 1 çıkış kriterine ekleme: shadow modunda gerçek MCP trafiği.
