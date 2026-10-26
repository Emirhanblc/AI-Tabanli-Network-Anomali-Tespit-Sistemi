# Model kartı

## Amaç ve veri

Model, CICIDS2017 MachineLearningCVE akış kayıtlarından dört sınıf üretir.
İndirme betiğinin varsayılanı, resmî CSV'lerin herkese açık Parquet dönüşümüdür
(`bvsam/cic-ids-2017`). Kaynak veri UNB CIC'nin CICIDS2017 veri setidir.

## Özellikler

Model sırasıyla `dst_port`, `packet_size`, `send_rate`, `syn`, `ack`
özelliklerini kullanır. Eğitimde bunlar Destination Port, Average Packet Size,
Flow Packets/s, SYN Flag Count ve ACK Flag Count kolonlarından türetilir.
Dinleyici aynı adları paket başlığı ve kaynak IP başına bir saniyelik pencereyle
üretir. IP adresleri ve kaynak port yalnızca olay kaydında tutulur.

## Eğitim sonucu

2026-10-26 eğitiminde 315.342 dengelenmiş kayıt kullanıldı. Ayrılmış test
kümesindeki doğruluk 0,9889; sınıf F1 değerleri Temiz 0,9832, DDoS 0,9936,
Brute Force 0,9705 ve Port Scan 0,9928 oldu. Tam rapor
`artifacts/metrics.json` dosyasındadır.

## Sınırlamalar

CICIDS2017 değerleri tamamlanmış akışların özetidir; canlı değerler tek paket ve
kısa pencere ölçümüdür. Bu dağılım farkı özellikle düşük hızlı tarama ile
şifreli brute-force trafiğinde yanlış pozitif/negatif oluşturabilir. Test
metrikleri canlı ağ başarısı olarak yorumlanmamalıdır. Üretim benzeri kullanım
için aynı çıkarıcıyla toplanmış etiketli laboratuvar verisiyle kalibrasyon
gerekir.

Sistem engelleme yapmaz. Yalnızca yetkili ağlarda savunma amaçlı kullanılmalıdır.
