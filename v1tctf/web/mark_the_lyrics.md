# Challenge: Mark the Lyrics
- Category: Web

## Description

<img width="670" height="523" alt="image" src="https://github.com/user-attachments/assets/dc191ab7-2a0a-4d6b-b8ee-a28844be61de" />


## Flag: 
`v1t{MCK-pap-cool-ooh-yeah}`

## Solution
Checking the source code, i didnt find anything suspicious at first but then because the challenge is called "mark" the lyrics i decided to check all the `<mark>` tags and the flag was basically hid letter by letter after every tag.
```html
   <div class="tag">{<mark>V</mark>erse <mark>1</mark>: Sơn Tùng M-<mark>T</mark>P}</div>
    <pre>Cứ-cứ-cứ-cứ quên anh vậy đi (Vậy đi)
Nhạt nhoà sương tan, ái ân, mây trôi buồn
Những môi hôn chìm sâu (Sâu)
Còn đâu nụ cười thơ ngây đó-đó?
Cứ xa anh vậy đi
Đường mòn xưa kia dẫn lối đôi chân lẻ loi, oh-oh, oh-oh-oh-oh
Anh lẻ loi</pre>
  </div>

  <div class="section">
    <div class="tag"><mark>{</mark>Pre-Chorus: Sơn Tùng M-TP}</div>
    <pre>Mưa rơi nhẹ rơi (Yeah, yeah), mưa đừng mang hoàng hôn xua tan bóng anh
Chua cay nào hay? (Yeah, yeah) Thương là đau, màn đêm chia hai giấc mơ
Giọt nước mắt vô tâm thờ ơ
Ngàn câu ca sao nghe hững hờ?
Anh lặng im, em lặng im
Sương gió bủa vây (Em lặng im), oh</pre>
  </div>

  <div class="section">
    <div class="tag">{Chorus: RPT <mark>MCK</mark>, Sơn Tùng M-TP}</div>
    <pre>Ooh-ooh-ooh, ooh-ooh-ooh-ooh
Ooh-ooh-ooh, ooh-ooh-ooh-ooh
(Buông đôi tay nhau ra, buông đôi tay chia xa)
Ooh-ooh-ooh, ooh-ooh-ooh-ooh
(Hờn ghen xin cất trong tim này)
Ooh-ooh-ooh, ooh-ooh-ooh-ooh
(Yeah, yeah, yeah)</pre>
  </div>

  <div class="section">
    <div class="tag">{Post-Chorus: Sơn Tùng M-TP}</div>
    <pre>(Hey) Ngày tháng êm ấm vụt mất (Ho)
Ai đó mang em đi rồi (Hey), giấu chôn những hoài mong (Ho)
Ở phía trước mong em bình (Hey, ho) yên phía sau những vụn vỡ (Ho)
Cơn gió quay lưng rồi (Hey) ngoái thương những chờ mong (Ho)
Oh-oh</pre>
  </div>

  <div class="section">
    <div class="tag">{Verse 2: RPT MCK}</div>
    <pre>Anh đã khác, em đã khác, uh-huh, I know that baby girl
Người yêu cũ em ghen với anh vì anh flow ác, baby girl
Bảo nó out ra khỏi hình luôn đi, đứng vào hình chỉ làm tăng contrast
Thích thì chơi, đấm vào đầu mày hai phát
Hai nhân hai, pap<mark>-pap-</mark>pap-pap
Trai tráng, nam nhi đại trượng phu
Nháy mắt <mark>cool</mark> cool, sợ đéo gì phốt ghẻ
Trông em tươi tắn, ưng con ngươi lắm
Một chốt yêu luôn, hai chốt đẻ
Mấy thằng anh em, cả mấy thằng em anh
Dạy anh biết đời thế nào là fair
Không tin may mắn, anh tin vào anh
Đại cát đại hung, ra chùa đốt quẻ
Uh-huh, uh-huh, anh em bọn anh cứ thế thôi
Huh-huh, anh lặng im chẳng nói được câu nào anh hóa đá, anh tê rồi
Huh-huh, hah, anh em bọn anh cứ thế thôi
Bao quanh anh ngực công mông thủ, nhưng mà tiêu chuẩn cao chỉ đẹp không đủ</pre>
  </div>

  <div class="section">
    <div class="tag">{Chorus: RPT MCK, Sơn Tùng M-TP}</div>
    <pre>Ooh-ooh-ooh, ooh-ooh-ooh-ooh
Buông đôi tay nhau ra, buông đôi tay nhau ra, hah
Ooh-ooh-ooh, ooh<mark>-ooh-</mark>ooh-ooh
Buông đôi tay nhau ra, buông đôi tay nhau ra, hah-ah-ah-ah
Ooh-ooh-ooh, ooh-ooh-ooh-ooh
Mình em xinh nhất trong tim này
Ooh-ooh-ooh, ooh-ooh-ooh-ooh
Yeah, <mark>yeah</mark>, yeah</pre>
  </div>

  <div class="section">
    <div class="tag">{Post-Chorus: RPT MCK, Sơn Tùng M-TP}</div>
    <pre>(Hey) Ngày tháng êm ấm vụt mất (Ho)
Ai đó mang em đi rồi (Hey), vấn vương những hoài mong (Ho)
Ở phía trước mong em bình (Hey, ho) yên phía sau những vụn vỡ (Ho)
Cơn gió quay lưng rồi (Hey) ngoái thương những chờ mong (Ho)
Oh-oh</pre>
  </div>

  <div class="section">
    <div class="tag">{Outro: Sơn Tùng M-TP, RPT MCK, RPT TC<mark>}</mark></div>
    <pre>Có lẽ
Anh sẽ quên đi tất cả
Phía trước đang chờ em
Chúc em hạnh phúc (Chúc em hạnh phúc)</pre>
  </div>
```
</body>

</html>
