#!/bin/bash
# Sansürsüz — Kurulum Scripti
# Bu script uygulamayı kurar ve başlatır.

APP_NAME="Sansursuz.app"
INSTALL_DIR="/Applications"

echo "🔓 Sansürsüz kuruluyor..."

# Find .app in same directory as this script
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

if [ ! -d "$SCRIPT_DIR/$APP_NAME" ]; then
    echo "❌ Hata: $APP_NAME bulunamadı!"
    echo "Bu scripti zip'ten çıkan dosyalarla aynı klasörde çalıştırın."
    read -p "Kapatmak için Enter'a basın..."
    exit 1
fi

# Remove quarantine
echo "🔧 Güvenlik ayarları yapılıyor..."
xattr -cr "$SCRIPT_DIR/$APP_NAME"

# Copy to Applications
echo "📦 Applications klasörüne kopyalanıyor..."
cp -R "$SCRIPT_DIR/$APP_NAME" "$INSTALL_DIR/" 2>/dev/null
if [ $? -ne 0 ]; then
    echo "⚠️  Applications'a kopyalanamadı (yetki sorunu olabilir)."
    echo "Uygulama mevcut konumundan başlatılacak."
    xattr -cr "$SCRIPT_DIR/$APP_NAME"
    open "$SCRIPT_DIR/$APP_NAME"
else
    xattr -cr "$INSTALL_DIR/$APP_NAME"
    echo "✅ Kurulum tamamlandı!"
    open "$INSTALL_DIR/$APP_NAME"
fi

echo ""
echo "🎉 Sansürsüz başlatıldı! Bu pencereyi kapatabilirsiniz."
sleep 3
