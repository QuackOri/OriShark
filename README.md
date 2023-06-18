# OriShark

pcap 파일을 읽고 분석해주는 파이썬 코드입니다. 
Layer들의 각 헤더를 class로 만들어 parse 하도록 구현하였습니다.

현재 읽을 수 있는 헤더:
- TCP
  - HTTP
- UDP
  - DNS

실행방법:
python main.py
