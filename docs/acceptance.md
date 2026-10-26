# Kabul testi kaydı

Otomatik kontroller geliştirme makinesinde, laboratuvar kontrolleri yalnızca
operatörün yetkili olduğu Kali Linux veya Ubuntu ağında yürütülür.

| Kriter | Durum | Kanıt / not |
| --- | --- | --- |
| K-01 sağlık ucu | Geçti | 2026-10-26: Docker API + PostgreSQL sağlıklı, `ready=true` |
| K-02 geçerli tahmin ve trafik kaydı | Geçti | 2026-10-26: Docker üzerinde tahmin ve `traffic_id=1` |
| K-03 422 ve kayıt açılmaması | Geçti (yerel) | 2026-10-26: HTTP 422, kayıt sayısı 1 olarak kaldı |
| K-04 port tarama uyarısı | Laboratuvar bekliyor | Yetkili ağ ve gerçek model gerekir |
| K-05 SYN flood uyarısı | Laboratuvar bekliyor | Yetkili ağ ve gerçek model gerekir |
| K-06 normal trafiğin yeşil listesi | Laboratuvar bekliyor | Panel ile gözlem |
| K-07 iki saniye gecikme | Laboratuvar bekliyor | Yakalama ve panel zamanları ölçülür |

K-04 ve K-05 için bu projede saldırı üretme komutu veya otomasyonu bulunmaz.
Sonuç kaydına tarih, arayüz, beklenen sınıf, trafik/uyarı kimliği ve panelde
görülme gecikmesi eklenmelidir.

2026-10-26 geliştirme kontrolünde `pytest` sonucu 9 geçti olarak kaydedildi.
Compose imajı oluşturuldu; API ve PostgreSQL konteynerleri sağlıklı duruma
geldi. Gerçek modelle `Temiz` tahmini trafik tablosuna başarıyla yazıldı.
