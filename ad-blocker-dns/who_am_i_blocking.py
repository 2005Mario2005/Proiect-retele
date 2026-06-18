domains = ["google", "quantummetric", "amazon", "facebook", "doubleclick", "yahoo", "mozilla", "ad-delivery", "scorecardresearch", "yandex", "rtmark", "sharethis"]
domain_dic = {}
for dom in domains:
    domain_dic[dom] = 0
with open("blocked.log","r") as f:
    for line in f.readlines():
        line = line.replace("BLOCKED: ", "")
        date, timestamp, domain = line.split()
        for dom in domains:
            if dom in domain:
                domain_dic[dom] += 1
                break

for domain in domains:
    print(f"{domain}: {domain_dic[domain]}")
        
