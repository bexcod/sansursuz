# Sansürsüz

Türkiye'deki internet sansürünü aşmak için tasarlanmış, kullanımı kolay bir araç.

## ✨ Özellikler

- 🔓 **Tek tıkla sansür aşma** — İndir, aç, butona bas
- 🌐 **Şifreli DNS** — Cloudflare, Google, Quad9, AdGuard, Yandex
- 🔍 **Akıllı tespit** — Engelli siteleri otomatik algılar
- 💻 **Tüm sistem** — 3. parti eklenti veya ayar gerekmez
- ⚡ **Hızlı** — Oyunları ve bankacılığı etkilemez
- 🖥️ **Çoklu platform** — macOS, Windows, Linux

## 📥 İndirme

[**Releases**](../../releases/latest) sayfasından platformunuza uygun dosyayı indirin:

| Platform | Dosya | Kurulum |
|---|---|---|
| macOS (M1/M2) | `sansursuz-macos-arm64.zip` | Zip'i açın → **Sansürsüz.app**'i Applications'a sürükleyin |
| macOS (Intel) | `sansursuz-macos-amd64.zip` | Zip'i açın → **Sansürsüz.app**'i Applications'a sürükleyin |
| Windows | `sansursuz-windows-amd64.exe` | İndirip çift tıklayın |
| Linux | `sansursuz-linux-amd64` | `chmod +x` yapıp çalıştırın |

## 🚀 Kullanım

1. İndirilen dosyaya çift tıklayın
2. Menü çubuğunda (macOS) veya sistem tepsisinde (Windows) **Sansürsüz** ikonu belirir
3. **⚙️ Ayarlar**'a tıklayarak tarayıcıda kontrol panelini açın
4. Büyük yeşil butona basarak açıp kapatın

### Ayarlar

| Ayar | Açıklama |
|---|---|
| **DNS Sağlayıcı** | Şifreli DNS sunucusu (varsayılan: Cloudflare) |
| **Şifreleme** | Akıllı (sadece engelli siteler) veya Tümü |
| **Port** | Proxy port numarası (varsayılan: 8443) |

## 🛡️ Güvenlik

- Admin/root yetkisi **gerektirmez**
- Sadece HTTP/HTTPS trafiğini yönlendirir — oyunlar, VoIP etkilenmez
- Bankacılık siteleri güvenle çalışır
- Verileriniz kaydedilmez, 3. parti sunuculara gönderilmez

## ⚠️ macOS İlk Çalıştırma

İlk açılışta **"hasar görmüş"** veya **"doğrulanamadı"** uyarısı alabilirsiniz. Çözmek için Terminal'de:
```bash
xattr -cr /Applications/Sansursuz.app
```
Ardından **Sansursuz.app**'e çift tıklayın — sorunsuz açılacaktır.

## 🔧 Geliştiriciler İçin

```bash
# Build
go build -o sansursuz ./cmd/sansursuz/

# Çalıştır
./sansursuz --no-gui
```

## 📄 Lisans

MIT License
